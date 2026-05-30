"""
services.py — Local service lookup table for defensivePortScanner.

Maps well-known TCP port numbers to (short_name, description) pairs.
This is purely inference based on port number convention (IANA assignments
and common practice). It does NOT reflect what is actually running on a host.

Source conventions: IANA Service Name and Transport Protocol Port Number Registry,
plus widely recognized non-IANA assignments (e.g. 3306/MySQL, 6379/Redis).
"""

from typing import NamedTuple


class ServiceInfo(NamedTuple):
    name: str  # Short service name shown in the SERVICE column
    description: str  # One-line description for verbose output


# ---------------------------------------------------------------------------
# Port → ServiceInfo lookup table
# ---------------------------------------------------------------------------
# Organised roughly by category for maintainability.

TCP_SERVICES: dict[int, ServiceInfo] = {
    # Remote access / shell
    22: ServiceInfo("SSH", "Secure Shell — encrypted remote login"),
    23: ServiceInfo("Telnet", "Unencrypted remote terminal (legacy)"),
    513: ServiceInfo("rlogin", "BSD remote login (legacy, plaintext)"),
    514: ServiceInfo("rsh/syslog", "Remote shell or UDP syslog"),
    # Web
    80: ServiceInfo("HTTP", "Hypertext Transfer Protocol"),
    443: ServiceInfo("HTTPS", "HTTP over TLS/SSL"),
    8080: ServiceInfo("HTTP-alt", "Common HTTP alternate / proxy port"),
    8443: ServiceInfo("HTTPS-alt", "Common HTTPS alternate port"),
    8008: ServiceInfo("HTTP-alt", "HTTP alternate port"),
    3000: ServiceInfo("HTTP-dev", "Common development web server port"),
    5000: ServiceInfo("HTTP-dev", "Flask / generic dev server default"),
    8888: ServiceInfo("HTTP-dev", "Jupyter Notebook default port"),
    # File transfer
    20: ServiceInfo("FTP-data", "FTP data channel (active mode)"),
    21: ServiceInfo("FTP", "File Transfer Protocol control channel"),
    69: ServiceInfo("TFTP", "Trivial File Transfer Protocol (UDP)"),
    115: ServiceInfo("SFTP", "Simple File Transfer Protocol (legacy)"),
    989: ServiceInfo("FTPS-data", "FTP-SSL data channel"),
    990: ServiceInfo("FTPS", "FTP-SSL control channel"),
    # Email
    25: ServiceInfo("SMTP", "Simple Mail Transfer Protocol"),
    465: ServiceInfo("SMTPS", "SMTP over TLS (legacy)"),
    587: ServiceInfo("SMTP-sub", "SMTP mail submission"),
    110: ServiceInfo("POP3", "Post Office Protocol v3"),
    995: ServiceInfo("POP3S", "POP3 over TLS"),
    143: ServiceInfo("IMAP", "Internet Message Access Protocol"),
    993: ServiceInfo("IMAPS", "IMAP over TLS"),
    # DNS & directory
    53: ServiceInfo("DNS", "Domain Name System"),
    389: ServiceInfo("LDAP", "Lightweight Directory Access Protocol"),
    636: ServiceInfo("LDAPS", "LDAP over TLS"),
    3268: ServiceInfo("LDAP-GC", "Active Directory Global Catalog"),
    3269: ServiceInfo("LDAPS-GC", "Active Directory Global Catalog over TLS"),
    # Network services
    67: ServiceInfo("DHCP-srv", "DHCP server (UDP)"),
    68: ServiceInfo("DHCP-cli", "DHCP client (UDP)"),
    123: ServiceInfo("NTP", "Network Time Protocol (UDP)"),
    161: ServiceInfo("SNMP", "Simple Network Management Protocol (UDP)"),
    162: ServiceInfo("SNMPTRAP", "SNMP Trap receiver"),
    179: ServiceInfo("BGP", "Border Gateway Protocol"),
    520: ServiceInfo("RIP", "Routing Information Protocol (UDP)"),
    # Windows / SMB / RPC
    135: ServiceInfo("MSRPC", "Microsoft RPC endpoint mapper"),
    137: ServiceInfo("NetBIOS-ns", "NetBIOS Name Service"),
    138: ServiceInfo("NetBIOS-dg", "NetBIOS Datagram Service (UDP)"),
    139: ServiceInfo("NetBIOS-ss", "NetBIOS Session Service"),
    445: ServiceInfo("SMB", "Server Message Block — file sharing"),
    593: ServiceInfo("MSRPC-HTTP", "Microsoft RPC over HTTP"),
    3389: ServiceInfo("RDP", "Remote Desktop Protocol"),
    5985: ServiceInfo("WinRM-HTTP", "Windows Remote Management (HTTP)"),
    5986: ServiceInfo("WinRM-HTTPS", "Windows Remote Management (HTTPS)"),
    # Databases
    1433: ServiceInfo("MSSQL", "Microsoft SQL Server"),
    1434: ServiceInfo("MSSQL-mon", "Microsoft SQL Server monitor (UDP)"),
    1521: ServiceInfo("Oracle", "Oracle Database listener"),
    3306: ServiceInfo("MySQL", "MySQL / MariaDB database"),
    5432: ServiceInfo("PostgreSQL", "PostgreSQL database"),
    5984: ServiceInfo("CouchDB", "Apache CouchDB HTTP API"),
    6379: ServiceInfo("Redis", "Redis in-memory data store"),
    7474: ServiceInfo("Neo4j", "Neo4j graph database HTTP API"),
    9200: ServiceInfo("Elasticsearch", "Elasticsearch HTTP API"),
    9300: ServiceInfo("ES-cluster", "Elasticsearch cluster transport"),
    27017: ServiceInfo("MongoDB", "MongoDB database"),
    27018: ServiceInfo("MongoDB", "MongoDB shard server"),
    27019: ServiceInfo("MongoDB", "MongoDB config server"),
    # Message brokers / queues
    4369: ServiceInfo("EPMD", "Erlang Port Mapper Daemon"),
    5671: ServiceInfo("AMQPS", "AMQP over TLS (RabbitMQ)"),
    5672: ServiceInfo("AMQP", "Advanced Message Queuing Protocol"),
    9092: ServiceInfo("Kafka", "Apache Kafka broker"),
    61613: ServiceInfo("STOMP", "Simple Text Oriented Messaging Protocol"),
    61614: ServiceInfo("STOMP-TLS", "STOMP over TLS"),
    61616: ServiceInfo("ActiveMQ", "Apache ActiveMQ broker"),
    # VPN / tunneling
    500: ServiceInfo("IKE", "Internet Key Exchange (IPsec, UDP)"),
    1194: ServiceInfo("OpenVPN", "OpenVPN (UDP or TCP)"),
    1701: ServiceInfo("L2TP", "Layer 2 Tunneling Protocol (UDP)"),
    1723: ServiceInfo("PPTP", "Point-to-Point Tunneling Protocol"),
    4500: ServiceInfo("IKE-NAT", "IPsec NAT traversal (UDP)"),
    51820: ServiceInfo("WireGuard", "WireGuard VPN (UDP)"),
    # Monitoring / management
    161: ServiceInfo("SNMP", "Simple Network Management Protocol"),
    199: ServiceInfo("SMUX", "SNMP Unix Multiplexer"),
    623: ServiceInfo("IPMI", "Intelligent Platform Management Interface"),
    5900: ServiceInfo("VNC", "Virtual Network Computing"),
    5901: ServiceInfo("VNC-1", "VNC display :1"),
    5902: ServiceInfo("VNC-2", "VNC display :2"),
    # Containers / orchestration
    2375: ServiceInfo(
        "Docker", "Docker daemon (unauthenticated — dangerous if exposed)"
    ),
    2376: ServiceInfo("Docker-TLS", "Docker daemon over TLS"),
    2379: ServiceInfo("etcd", "etcd client port (Kubernetes)"),
    2380: ServiceInfo("etcd-peer", "etcd peer port"),
    6443: ServiceInfo("K8s-API", "Kubernetes API server (HTTPS)"),
    10250: ServiceInfo("Kubelet", "Kubernetes Kubelet API"),
    10255: ServiceInfo("Kubelet-ro", "Kubernetes Kubelet read-only API"),
    # Miscellaneous well-known
    7: ServiceInfo("Echo", "TCP/UDP Echo service"),
    9: ServiceInfo("Discard", "Discard / Wake-on-LAN (UDP)"),
    13: ServiceInfo("Daytime", "Daytime protocol"),
    19: ServiceInfo("Chargen", "Character Generator (can be abused for DDoS)"),
    37: ServiceInfo("Time", "Time protocol"),
    79: ServiceInfo("Finger", "Finger user information protocol (legacy)"),
    111: ServiceInfo("RPCbind", "ONC RPC portmapper"),
    119: ServiceInfo("NNTP", "Network News Transfer Protocol"),
    194: ServiceInfo("IRC", "Internet Relay Chat"),
    6667: ServiceInfo("IRC", "IRC (unencrypted, common default)"),
    6697: ServiceInfo("IRC-TLS", "IRC over TLS"),
    1080: ServiceInfo("SOCKS", "SOCKS proxy"),
    3128: ServiceInfo("Squid", "Squid HTTP proxy"),
    8123: ServiceInfo("Home-Asst", "Home Assistant web interface"),
}


def lookup(port: int) -> ServiceInfo | None:
    """
    Return the ServiceInfo for a known port, or None if unrecognised.
    This is inference only — it reflects the conventional assignment,
    not what is actually listening on the scanned host.
    """
    return TCP_SERVICES.get(port)


def service_name(port: int) -> str:
    """
    Return the short service name for a port, or 'unknown' if not in the table.
    Convenience wrapper used by the output formatter.
    """
    info = lookup(port)
    return info.name if info else "unknown"
