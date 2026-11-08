"""Safe RPC Guard & Anti-SSRF Defense Module (forensics/rpc_guard.py).

Provides enterprise-grade SSRF defense and strict read-only JSON-RPC enforcement:
1. DNS pre-resolution checking all resolved IP addresses before connection.
2. Comprehensive IP blocking:
   - Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7
   - Cloud instance metadata: 169.254.169.254 (AWS, GCP, Azure, Oracle), 169.254.0.0/16, fe80::/10, fd00:ec2::254
   - Loopback: 127.0.0.0/8, ::1 (strictly blocked unless allow_local=True for authorized Anvil testing)
   - Multicast, broadcast, unspecified, and reserved ranges
3. HTTP redirect denial (_NoRedirectHandler) to eliminate SSRF redirect evasion.
4. Authorized RPC allowlists (Sepolia, Ethereum Mainnet, and local Anvil when explicitly authorized).
5. Strict read-only JSON-RPC enforcement: rejects state-modifying methods (eth_sendTransaction,
   eth_sendRawTransaction, personal_sign, etc.) and allows only forensic read methods.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("forensics.rpc_guard")


class SSRFSecurityError(ValueError):
    """Raised when an RPC request targets a blocked or unsafe IP/host."""
    pass


class ReadOnlyViolationError(PermissionError):
    """Raised when an RPC request attempts to execute state-modifying or signing methods."""
    pass


class RpcAllowlistError(PermissionError):
    """Raised when an RPC URL is not within the authorized allowlist."""
    pass


class RpcConnectionError(RuntimeError):
    """Raised when an authorized RPC node cannot be reached or returns an RPC error."""
    pass


# ==============================================================================
# IP RANGE DEFINITIONS FOR STRICT SSRF DEFENSE
# ==============================================================================

# Cloud Instance Metadata endpoints (AWS, GCP, Azure, Oracle, OpenStack)
CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
}

# Link-local networks (IPv4 169.254.0.0/16 & IPv6 fe80::/10)
LINK_LOCAL_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

# Private IP networks (RFC 1918 & RFC 4193 Unique Local)
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]

# Reserved, Multicast, Carrier-Grade NAT, and Unspecified networks
BLOCKED_SPECIAL_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Unspecified / Current network
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (CGNAT)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation (TEST-NET-1)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),        # IPv4 Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    ipaddress.ip_network("::/128"),             # IPv6 Unspecified
    ipaddress.ip_network("ff00::/8"),           # IPv6 Multicast
    ipaddress.ip_network("2001:db8::/32"),      # IPv6 Documentation
]

# Loopback networks (127.0.0.0/8 & ::1)
LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def check_ssrf_safety(ip_str: str, allow_local: bool = False) -> bool:
    """Evaluates whether an IP address is safe to connect to for live RPC investigation.

    Args:
        ip_str: The IP address string (IPv4 or IPv6).
        allow_local: If True, loopback addresses (127.0.0.0/8, ::1) are permitted for local Anvil.
                     Cloud metadata and private networks remain strictly blocked.

    Returns:
        True if the IP is a safe, routable public address (or authorized loopback), False otherwise.
    """
    clean_ip = ip_str.strip()
    if clean_ip.startswith("[") and clean_ip.endswith("]"):
        clean_ip = clean_ip[1:-1]

    try:
        ip = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False

    # 1. Cloud instance metadata: ALWAYS blocked
    if ip in CLOUD_METADATA_IPS:
        return False

    for net in LINK_LOCAL_NETWORKS:
        if ip in net:
            return False

    # 2. Private IP networks: ALWAYS blocked
    for net in PRIVATE_NETWORKS:
        if ip in net:
            return False

    # 3. Special reserved / multicast / broadcast / CGNAT networks: ALWAYS blocked
    for net in BLOCKED_SPECIAL_NETWORKS:
        if ip in net:
            return False

    # 4. Loopback networks (127.0.0.0/8 and ::1)
    for net in LOOPBACK_NETWORKS:
        if ip in net:
            return bool(allow_local)

    # 5. Generic python ipaddress safety check
    if ip.is_private or ip.is_reserved or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        return False

    if ip.is_loopback:
        return bool(allow_local)

    return True


def resolve_and_verify_host(hostname: str, port: Optional[int] = None, allow_local: bool = False) -> List[str]:
    """Resolves DNS for a hostname and verifies that all returned IP addresses are safe.

    Args:
        hostname: The domain name or IP string.
        port: Optional port number.
        allow_local: Whether loopback is allowed.

    Returns:
        List of verified safe IP address strings.

    Raises:
        SSRFSecurityError: If any resolved IP violates SSRF defense rules.
    """
    clean_host = hostname.strip().lower()
    if clean_host.startswith("[") and clean_host.endswith("]"):
        clean_host = clean_host[1:-1]

    # Explicit loopback host check
    if clean_host in ("localhost", "localhost.localdomain") or clean_host.endswith(".localhost"):
        if not allow_local:
            raise SSRFSecurityError(
                f"Truy cập host nội bộ loopback '{hostname}' bị từ chối chống SSRF (chưa bật allow_local)."
            )

    # If it is already a literal IP address
    try:
        literal_ip = ipaddress.ip_address(clean_host)
        if not check_ssrf_safety(str(literal_ip), allow_local=allow_local):
            raise SSRFSecurityError(
                f"Địa chỉ IP '{clean_host}' thuộc dải mạng bị chặn chống SSRF (Private/Metadata/Loopback)."
            )
        return [str(literal_ip)]
    except ValueError:
        pass

    # Resolve hostname via getaddrinfo
    target_port = port if port else 443
    try:
        addr_info = socket.getaddrinfo(clean_host, target_port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as ge:
        raise SSRFSecurityError(f"Không thể phân giải DNS cho hostname '{hostname}': {ge}") from ge

    resolved_ips: List[str] = []
    seen: Set[str] = set()
    for item in addr_info:
        sockaddr = item[4]
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            resolved_ips.append(ip)

    if not resolved_ips:
        raise SSRFSecurityError(f"Phân giải DNS cho '{hostname}' không trả về địa chỉ IP nào.")

    for ip in resolved_ips:
        if not check_ssrf_safety(ip, allow_local=allow_local):
            raise SSRFSecurityError(
                f"Hostname '{hostname}' phân giải ra IP '{ip}' nằm trong dải mạng bị cấm chống SSRF."
            )

    return resolved_ips


# ==============================================================================
# AUTHORIZED RPC ALLOWLIST
# ==============================================================================

DEFAULT_ALLOWED_RPC_HOSTS: Set[str] = {
    # Sepolia Testnet (Chain ID 11155111)
    "rpc.sepolia.org",
    "sepolia.infura.io",
    "ethereum-sepolia-rpc.publicnode.com",
    "rpc2.sepolia.org",
    "1rpc.io",
    "sepolia.drpc.org",
    "rpc-sepolia.rockx.com",
    "endpoints.omniatech.io",
    # Ethereum Mainnet (Chain ID 1)
    "eth.llamarpc.com",
    "ethereum-rpc.publicnode.com",
    "rpc.ankr.com",
    "cloudflare-eth.com",
    "mainnet.infura.io",
    "1rpc.io",
    "eth.drpc.org",
    "eth-mainnet.public.blastapi.io",
}

DEFAULT_ALLOWED_URL_PREFIXES: List[str] = [
    "https://rpc.sepolia.org",
    "https://sepolia.infura.io",
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://rpc2.sepolia.org",
    "https://1rpc.io/sepolia",
    "https://eth.llamarpc.com",
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.ankr.com/eth",
    "https://cloudflare-eth.com",
    "https://mainnet.infura.io",
    "https://1rpc.io/eth",
]


def is_rpc_url_allowed(url: str, allowlist: Optional[List[str]] = None, allow_local: bool = False) -> bool:
    """Verifies whether an RPC URL is within the authorized allowlist.

    Args:
        url: The RPC endpoint URL.
        allowlist: Optional explicit list of allowed domains or URL prefixes.
        allow_local: If True, loopback Anvil endpoints are permitted.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        return False

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False

    # Check local Anvil authorization
    if allow_local and hostname in ("127.0.0.1", "localhost", "::1"):
        return True

    # If explicit allowlist provided, check against it
    if allowlist is not None and len(allowlist) > 0:
        for entry in allowlist:
            clean_entry = entry.strip().lower()
            if clean_entry == hostname:
                return True
            if url.lower().startswith(clean_entry):
                return True
            # Wildcard or suffix match (e.g. *.sepolia.infura.io)
            if clean_entry.startswith("*.") and hostname.endswith(clean_entry[1:]):
                return True
            if clean_entry in hostname:
                return True
        return False

    # Check default allowlist
    if hostname in DEFAULT_ALLOWED_RPC_HOSTS:
        return True

    for prefix in DEFAULT_ALLOWED_URL_PREFIXES:
        if url.lower().startswith(prefix.lower()):
            return True

    return False


def validate_rpc_url(
    url: str,
    allowlist: Optional[List[str]] = None,
    allow_local: bool = False,
    raise_on_error: bool = False,
) -> bool:
    """Performs full pre-flight validation on an RPC URL:
    1. Scheme and syntax checks (rejects embedded credentials, fragments, whitespace).
    2. Performs DNS pre-resolution and blocks SSRF addresses (private, metadata, loopback).
    3. Enforces HTTPS for all remote endpoints (HTTP only permitted for authorized loopback).
    4. Verifies against authorized RPC allowlist.

    Args:
        url: The candidate RPC URL.
        allowlist: Optional custom allowlist.
        allow_local: Whether local Anvil loopback is explicitly authorized.
        raise_on_error: If True, raises descriptive exceptions; if False, returns boolean.

    Returns:
        True if completely valid and safe, False otherwise.
    """
    if not url or not isinstance(url, str):
        if raise_on_error:
            raise ValueError("URL RPC không được để trống.")
        return False

    clean_url = url.strip()
    if any(c.isspace() or ord(c) < 32 for c in clean_url):
        if raise_on_error:
            raise ValueError("URL RPC chứa ký tự điều khiển hoặc khoảng trắng không hợp lệ.")
        return False

    try:
        parsed = urllib.parse.urlsplit(clean_url)
    except Exception as e:
        if raise_on_error:
            raise ValueError(f"URL RPC không đúng định dạng: {e}")
        return False

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        if raise_on_error:
            raise ValueError("URL RPC chỉ chấp nhận giao thức http:// hoặc https://.")
        return False

    if not parsed.hostname:
        if raise_on_error:
            raise ValueError("URL RPC thiếu tên máy chủ (hostname).")
        return False

    # Block embedded credentials (e.g. http://user:pass@host)
    if parsed.username or parsed.password:
        if raise_on_error:
            raise SSRFSecurityError("URL RPC không được chứa thông tin xác thực nhúng (user:pass).")
        return False

    # Block fragments
    if parsed.fragment:
        if raise_on_error:
            raise ValueError("URL RPC không được chứa thành phần fragment (#).")
        return False

    hostname = parsed.hostname.lower()
    is_loopback = hostname in ("127.0.0.1", "localhost", "::1")

    # 1. Literal IP SSRF check & loopback check
    clean_host_str = hostname[1:-1] if hostname.startswith("[") and hostname.endswith("]") else hostname
    try:
        literal_ip = ipaddress.ip_address(clean_host_str)
        if not check_ssrf_safety(str(literal_ip), allow_local=allow_local):
            if raise_on_error:
                raise SSRFSecurityError(
                    f"Địa chỉ IP '{hostname}' thuộc dải mạng bị chặn chống SSRF (Private/Metadata/Loopback)."
                )
            return False
    except ValueError:
        pass

    if is_loopback and not allow_local:
        if raise_on_error:
            raise SSRFSecurityError(
                f"Truy cập host loopback '{hostname}' bị từ chối chống SSRF (chưa bật allow_local)."
            )
        return False

    # 2. Enforce HTTPS on non-loopback endpoints
    if not is_loopback and scheme != "https":
        if raise_on_error:
            raise SSRFSecurityError(
                f"RPC ngoài máy cục bộ bắt buộc sử dụng HTTPS mã hóa (endpoint '{clean_url}' dùng HTTP không an toàn)."
            )
        return False

    # 3. Check Allowlist
    if not is_rpc_url_allowed(clean_url, allowlist=allowlist, allow_local=allow_local):
        if raise_on_error:
            raise RpcAllowlistError(
                f"Endpoint RPC '{clean_url}' không nằm trong danh sách cấp quyền được phê duyệt."
            )
        return False

    # 4. DNS pre-resolution & Anti-SSRF check on all resolved IPs (prevents DNS rebinding)
    try:
        resolve_and_verify_host(hostname, port=parsed.port, allow_local=allow_local)
    except SSRFSecurityError:
        if raise_on_error:
            raise
        return False
    except Exception as e:
        if raise_on_error:
            raise SSRFSecurityError(f"Lỗi kiểm tra an toàn DNS/SSRF: {e}")
        return False

    return True



# ==============================================================================
# HTTP REDIRECT DENIAL (ANTI-REDIRECT SSRF)
# ==============================================================================

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom HTTP redirect handler that rejects all HTTP redirects to defeat SSRF redirect evasion."""

    def http_error_301(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        loc = headers.get("Location", "") if headers else ""
        raise SSRFSecurityError(f"Chuyển hướng HTTP {code} tới '{loc}' bị từ chối để ngăn tấn công SSRF.")

    def http_error_302(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        loc = headers.get("Location", "") if headers else ""
        raise SSRFSecurityError(f"Chuyển hướng HTTP {code} tới '{loc}' bị từ chối để ngăn tấn công SSRF.")

    def http_error_303(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        loc = headers.get("Location", "") if headers else ""
        raise SSRFSecurityError(f"Chuyển hướng HTTP {code} tới '{loc}' bị từ chối để ngăn tấn công SSRF.")

    def http_error_307(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        loc = headers.get("Location", "") if headers else ""
        raise SSRFSecurityError(f"Chuyển hướng HTTP {code} tới '{loc}' bị từ chối để ngăn tấn công SSRF.")

    def http_error_308(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        loc = headers.get("Location", "") if headers else ""
        raise SSRFSecurityError(f"Chuyển hướng HTTP {code} tới '{loc}' bị từ chối để ngăn tấn công SSRF.")

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise SSRFSecurityError(
            f"Máy chủ phản hồi chuyển hướng HTTP {code} tới '{newurl}'. Thao tác bị chặn để ngăn tấn công SSRF."
        )



# ==============================================================================
# STRICT READ-ONLY METHOD ENFORCEMENT
# ==============================================================================

ALLOWED_READ_METHODS: Set[str] = {
    "eth_blockNumber",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getLogs",
    "eth_chainId",
    "eth_getBalance",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_call",
    "eth_getTransactionCount",
    "eth_estimateGas",
    "net_version",
    "web3_clientVersion",
}

FORBIDDEN_STATE_METHODS: Set[str] = {
    "eth_sendTransaction",
    "eth_sendRawTransaction",
    "personal_sign",
    "personal_sendTransaction",
    "eth_sign",
    "eth_signTransaction",
    "eth_signTypedData",
    "eth_signTypedData_v4",
    "wallet_sendCalls",
    "eth_accounts",
    "personal_unlockAccount",
    "personal_newAccount",
}


def is_read_only_method(method: str) -> bool:
    """Returns True if method is an authorized read-only forensic method."""
    clean = method.strip()
    return clean in ALLOWED_READ_METHODS and clean not in FORBIDDEN_STATE_METHODS


def assert_read_only_method(method: str) -> None:
    """Validates that a JSON-RPC method is strictly read-only.

    Raises:
        ReadOnlyViolationError: If the method alters state or signs data.
    """
    clean = method.strip()
    if clean in FORBIDDEN_STATE_METHODS:
        raise ReadOnlyViolationError(
            f"Phương thức thay đổi trạng thái hoặc ký số '{method}' bị nghiêm cấm trong chế độ điều tra giám định chỉ đọc."
        )
    if clean not in ALLOWED_READ_METHODS:
        raise ReadOnlyViolationError(
            f"Phương thức '{method}' không nằm trong danh mục JSON-RPC chỉ đọc được cấp phép."
        )


# ==============================================================================
# SAFE JSON-RPC CLIENT CALLER
# ==============================================================================

def safe_rpc_call(
    rpc_url: str,
    method: str,
    params: Optional[List[Any]] = None,
    allow_local: bool = False,
    allowlist: Optional[List[str]] = None,
    timeout: int = 15,
) -> Any:
    """Executes a safe, read-only JSON-RPC call protected against SSRF and redirect attacks.

    Args:
        rpc_url: The RPC endpoint.
        method: The JSON-RPC method to call (must be read-only).
        params: List of arguments.
        allow_local: Whether local Anvil is permitted.
        allowlist: Optional custom allowlist.
        timeout: Network timeout in seconds.

    Returns:
        The result field of the JSON-RPC response.

    Raises:
        ReadOnlyViolationError: If method is state-modifying.
        SSRFSecurityError: If URL fails anti-SSRF checks or attempts a redirect.
        RpcAllowlistError: If URL is not in allowlist.
        RpcConnectionError: If network error or JSON-RPC returns error.
    """
    # 1. Enforce read-only method
    assert_read_only_method(method)

    # 2. Validate URL and SSRF safety with DNS pre-resolution
    validate_rpc_url(rpc_url, allowlist=allowlist, allow_local=allow_local, raise_on_error=True)

    # 3. Build payload
    payload_data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params if params is not None else [],
        "id": 1,
    }
    raw_payload = json.dumps(payload_data).encode("utf-8")

    # 4. Configure opener with redirect blocking
    opener = urllib.request.build_opener(_NoRedirectHandler())
    req = urllib.request.Request(
        rpc_url,
        data=raw_payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Blockchain-Ai-Aigital-Forensics/1.0",
            "Accept": "application/json",
        },
    )

    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except SSRFSecurityError:
        raise
    except urllib.error.HTTPError as he:
        raise RpcConnectionError(f"Lỗi phản hồi HTTP từ RPC ({he.code}): {he.reason}") from he
    except urllib.error.URLError as ue:
        raise RpcConnectionError(f"Không thể kết nối tới node RPC: {ue.reason}") from ue
    except socket.timeout as te:
        raise RpcConnectionError(f"Hết thời gian chờ phản hồi ({timeout}s) từ RPC: {te}") from te
    except Exception as e:
        raise RpcConnectionError(f"Lỗi kết nối RPC: {e}") from e

    try:
        res_json = json.loads(body)
    except Exception as je:
        raise RpcConnectionError(f"Dữ liệu phản hồi từ RPC không phải JSON hợp lệ: {je}") from je

    if not isinstance(res_json, dict):
        raise RpcConnectionError("Dữ liệu phản hồi JSON-RPC không đúng định dạng đối tượng.")

    if "error" in res_json and res_json["error"] is not None:
        err_msg = res_json["error"].get("message", str(res_json["error"])) if isinstance(res_json["error"], dict) else str(res_json["error"])
        raise RpcConnectionError(f"Node RPC trả về lỗi JSON-RPC: {err_msg}")

    if "result" not in res_json:
        raise RpcConnectionError("Phản hồi JSON-RPC không chứa trường 'result'.")

    return res_json["result"]
