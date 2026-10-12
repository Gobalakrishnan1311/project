import ipaddress
import socket
from urllib.parse import urlparse
from typing import Optional, List, Tuple

class ScopeGuardError(Exception):
    pass

class ScopeGuard:
    PROHIBITED_METADATA_IPS = {
        "169.254.169.254",
        "metadata.google.internal",
        "100.100.100.200",  # Alibaba Cloud metadata
    }

    @staticmethod
    def is_private_or_reserved_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            # IPv4 checks
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                return True
            # AWS/GCP link-local metadata range
            if ip_str.startswith("169.254."):
                return True
            return False
        except ValueError:
            return True

    @classmethod
    def normalize_target(cls, raw_url: str) -> Tuple[str, str, str]:
        url = raw_url.strip()
        if not url:
            raise ScopeGuardError("Target URL or domain cannot be empty.")

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ScopeGuardError(f"Malformed URL: {str(e)}")

        if parsed.scheme.lower() not in ("http", "https"):
            raise ScopeGuardError(f"Prohibited scheme: '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

        hostname = parsed.hostname
        if not hostname:
            raise ScopeGuardError("Could not determine hostname from target.")

        hostname = hostname.lower()

        # Reject loopback literals & obvious metadata hostnames
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            raise ScopeGuardError("Access to localhost / loopback is prohibited by ScopeGuard.")

        if hostname in cls.PROHIBITED_METADATA_IPS:
            raise ScopeGuardError("Access to cloud metadata endpoints is prohibited.")

        normalized_url = f"{parsed.scheme.lower()}://{hostname}"
        if parsed.port and ((parsed.scheme == 'http' and parsed.port != 80) or (parsed.scheme == 'https' and parsed.port != 443)):
            normalized_url += f":{parsed.port}"
        if parsed.path:
            normalized_url += parsed.path
        if parsed.query:
            normalized_url += f"?{parsed.query}"

        return normalized_url, hostname, parsed.scheme.lower()

    @classmethod
    def validate_destination_network(
        cls,
        target_url: str,
        allowed_host: Optional[str] = None,
        allow_subdomains: bool = False,
        excluded_hosts: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        user_authorized: bool = True
    ) -> Tuple[str, str, str]:
        normalized_url, hostname, scheme = cls.normalize_target(target_url)

        if not user_authorized:
            raise ScopeGuardError("Target is not authorized. Explicit authorization is mandatory before scanning.")

        # Check scope allowlist if defined
        if allowed_host:
            allowed = allowed_host.lower()
            is_exact = hostname == allowed
            is_subdomain = allow_subdomains and hostname.endswith("." + allowed)
            if not is_exact and not is_subdomain:
                raise ScopeGuardError(f"Host '{hostname}' is out of approved scope ({allowed}).")

        # Exclusions check
        if excluded_hosts and any(ex.lower() == hostname for ex in excluded_hosts):
            raise ScopeGuardError(f"Host '{hostname}' is in the target exclusion list.")

        parsed = urlparse(normalized_url)
        if excluded_paths and any(parsed.path.startswith(p) for p in excluded_paths):
            raise ScopeGuardError(f"Path '{parsed.path}' is explicitly excluded from scan scope.")

        # Resolve IP addresses and verify SSRF protection
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = set(item[4][0] for item in addr_info)
        except socket.gaierror as e:
            raise ScopeGuardError(f"DNS resolution failure for '{hostname}': {str(e)}")

        if not resolved_ips:
            raise ScopeGuardError(f"DNS returned no IP addresses for '{hostname}'.")

        for ip_addr in resolved_ips:
            if cls.is_private_or_reserved_ip(ip_addr):
                raise ScopeGuardError(
                    f"ScopeGuard Blocked: '{hostname}' resolves to private/reserved IP {ip_addr} (SSRF prevention)."
                )

        primary_ip = list(resolved_ips)[0]
        return normalized_url, hostname, primary_ip
