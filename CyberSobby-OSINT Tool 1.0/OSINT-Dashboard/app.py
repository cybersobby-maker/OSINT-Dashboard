import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import requests
from flask import Flask, render_template, request

app = Flask(__name__)

# Public data services. These may occasionally be unavailable.
IP_API = "https://ipwho.is/"
RDAP_API = "https://rdap.org/domain/"

DOMAIN_LABEL = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"]

HTTP = requests.Session()
HTTP.headers.update({
    "User-Agent": "CyberSobby-OSINT-Dashboard/1.0 (educational project)"
})


def normalize_domain(value):
    """Accept a domain or URL, then validate its hostname."""
    value = value.strip()

    if not value:
        raise ValueError("Enter a domain name.")

    if "://" in value:
        parsed = urlsplit(value)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Use a URL beginning with http:// or https://.")

        host = parsed.hostname
    else:
        # Also accept inputs such as example.com/path
        host = value.split("/", 1)[0]
        host = host.split("?", 1)[0].split("#", 1)[0]

    if not host:
        raise ValueError("Could not find a domain in that input.")

    host = host.rstrip(".").lower()

    # Convert internationalized domain names to ASCII for validation.
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("The domain name is not valid.")

    # This dashboard accepts domains, rather than direct IP addresses.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name, not an IP address.")

    if len(host) > 253:
        raise ValueError("The domain name is too long.")

    labels = host.split(".")

    if len(labels) < 2 or any(
        not DOMAIN_LABEL.fullmatch(label) for label in labels
    ):
        raise ValueError(
            "Enter a valid domain, such as example.com."
        )

    return host


def lookup_dns(domain):
    """Look up common DNS record types."""
    records = {}
    errors = {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(
                domain,
                record_type,
                lifetime=3
            )

            values = []

            for answer in answers:
                if record_type == "MX":
                    value = (
                        f"{answer.preference} "
                        f"{str(answer.exchange).rstrip('.')}"
                    )
                else:
                    value = answer.to_text()

                values.append(value)

            records[record_type] = values

        except dns.resolver.NoAnswer:
            records[record_type] = []

        except dns.resolver.NXDOMAIN:
            records[record_type] = []

        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.resolver.LifetimeTimeout,
        ):
            records[record_type] = []
            errors[record_type] = "DNS query timed out or failed."

        except Exception:
            records[record_type] = []
            errors[record_type] = "Could not retrieve this record."

    return records, errors


def get_public_ip_addresses(records):
    """Keep valid, globally routable IP addresses."""
    public_ips = []

    for value in records.get("A", []) + records.get("AAAA", []):
        try:
            address = ipaddress.ip_address(value)

            if address.is_global and value not in public_ips:
                public_ips.append(value)

        except ValueError:
            continue

    return public_ips


def lookup_ip_info(ip_address):
    """Enrich one public IP using the ipwho.is service."""
    try:
        response = HTTP.get(
            IP_API + ip_address,
            timeout=6
        )
        response.raise_for_status()

        data = response.json()

        if not data.get("success", False):
            return {
                "ip": ip_address,
                "error": data.get(
                    "message",
                    "The IP information service returned no data."
                )
            }

        connection = data.get("connection") or {}
        timezone_data = data.get("timezone") or {}

        return {
            "ip": data.get("ip", ip_address),
            "type": data.get("type"),
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "isp": connection.get("isp"),
            "organization": connection.get("org"),
            "asn": connection.get("asn"),
            "timezone": timezone_data.get("id"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "error": None,
        }

    except requests.RequestException:
        return {
            "ip": ip_address,
            "error": "IP enrichment service is unavailable or timed out."
        }

    except ValueError:
        return {
            "ip": ip_address,
            "error": "The IP service returned invalid JSON."
        }


def extract_registrar(data):
    """Read the registrar's display name from an RDAP response."""
    for entity in data.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue

        vcard = entity.get("vcardArray", [])

        if len(vcard) < 2:
            continue

        for item in vcard[1]:
            if len(item) >= 4 and item[0] in ("fn", "org"):
                value = item[3]

                if isinstance(value, list):
                    return " ".join(str(part) for part in value)

                if value:
                    return str(value)

    return None


def lookup_rdap(domain):
    """Retrieve public domain registration data through RDAP."""
    try:
        response = HTTP.get(
            RDAP_API + domain,
            timeout=8
        )

        if response.status_code == 404:
            return {
                "available": False,
                "message": "No RDAP registration record was found."
            }

        response.raise_for_status()
        data = response.json()

        events = []

        for event in data.get("events", []):
            events.append({
                "action": event.get("eventAction", "Unknown"),
                "date": event.get("eventDate", "Not listed")
            })

        nameservers = [
            item.get("ldhName")
            for item in data.get("nameservers", [])
            if item.get("ldhName")
        ]

        return {
            "available": True,
            "handle": data.get("handle"),
            "registrar": extract_registrar(data),
            "statuses": data.get("status", []),
            "events": events,
            "nameservers": nameservers,
        }

    except requests.RequestException:
        return {
            "available": False,
            "message": "RDAP service is unavailable or timed out."
        }

    except ValueError:
        return {
            "available": False,
            "message": "The RDAP service returned invalid JSON."
        }


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None
    entered_domain = ""

    if request.method == "POST":
        entered_domain = request.form.get("domain", "")

        try:
            domain = normalize_domain(entered_domain)

            dns_records, dns_errors = lookup_dns(domain)
            ip_addresses = get_public_ip_addresses(dns_records)

            # Enrich only one public IP to reduce API usage.
            if ip_addresses:
                ip_info = lookup_ip_info(ip_addresses[0])
            else:
                ip_info = {
                    "error": (
                        "No public A or AAAA address was found. "
                        "IP enrichment was skipped."
                    )
                }

            rdap_info = lookup_rdap(domain)

            results = {
                "domain": domain,
                "checked_at": datetime.now(
                    timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "dns": dns_records,
                "dns_errors": dns_errors,
                "ip_addresses": ip_addresses,
                "ip_info": ip_info,
                "rdap": rdap_info,
            }

        except ValueError as exc:
            error = str(exc)

    return render_template(
        "index.html",
        results=results,
        error=error,
        entered_domain=entered_domain
    )


if __name__ == "__main__":
    # Local development only. Do not expose Flask's debug server publicly.
    app.run(debug=True)