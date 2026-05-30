"""
risk.py — Exposure risk classification for defensivePortScanner.

Classifies the risk of having a TCP port open and generates defensive
recommendations based on port conventions and, where available, banner text.

Design constraints
------------------
- This module does NOT claim that a vulnerability exists or has been exploited.
- Risk levels are based solely on the conventional use of a port number and
  any contextual information available from the banner.
- All assessments carry an explicit disclaimer reinforcing this limitation.

Public API
----------
  assess(port, service_name, banner_raw) -> RiskAssessment
  assess_results(results)               -> list[RiskAssessment]
"""

from __future__ import annotations

from enum import Enum
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Standard disclaimer (attached to every RiskAssessment)
# ---------------------------------------------------------------------------

DISCLAIMER: str = (
    "Risk levels are based on port conventions only. "
    "No vulnerability has been confirmed. "
    "Verify findings manually before taking action."
)


# ---------------------------------------------------------------------------
# RiskLevel
# ---------------------------------------------------------------------------


class RiskLevel(Enum):
    INFO = "info"  # Expected/normal, no action needed
    LOW = "low"  # Noteworthy, monitor
    MEDIUM = "medium"  # Review recommended
    HIGH = "high"  # Prompt action recommended
    CRITICAL = "critical"  # Should not be exposed; remediate immediately


# ---------------------------------------------------------------------------
# RiskAssessment
# ---------------------------------------------------------------------------


class RiskAssessment(NamedTuple):
    port: int
    service: str
    level: RiskLevel
    reason: str  # One sentence explaining why this level was assigned
    recommendation: str  # One or two sentences of defensive guidance
    disclaimer: str  # Always DISCLAIMER


# ---------------------------------------------------------------------------
# Port rules table
# _PORT_RULES[port] = (RiskLevel, reason, recommendation)
# ---------------------------------------------------------------------------

_PORT_RULES: dict[int, tuple[RiskLevel, str, str]] = {
    # ------------------------------------------------------------------
    # Remote access / shell
    # ------------------------------------------------------------------
    22: (
        RiskLevel.MEDIUM,
        "SSH is the standard encrypted remote-access protocol but is a "
        "frequent target for brute-force and credential-stuffing attacks.",
        "Restrict access with firewall rules or an allowlist of source IPs. "
        "Enforce public-key authentication and disable password login.",
    ),
    23: (
        RiskLevel.CRITICAL,
        "Telnet transmits credentials and all session data in plaintext and "
        "has no modern security mitigations.",
        "Disable Telnet immediately and replace it with SSH. "
        "There is no safe use case for Telnet on a network-accessible interface.",
    ),
    513: (
        RiskLevel.CRITICAL,
        "rlogin is a legacy BSD remote-login protocol that passes credentials "
        "in plaintext and relies on IP-address trust, which is trivially spoofed.",
        "Disable rlogin and use SSH instead. "
        "Block this port at the perimeter firewall.",
    ),
    514: (
        RiskLevel.CRITICAL,
        "rsh (remote shell) sends commands and data in plaintext with no "
        "authentication beyond IP-address trust.",
        "Disable rsh and replace it with SSH. "
        "Block port 514 TCP at the firewall; UDP 514 used for syslog may be "
        "kept if needed but should be restricted to trusted sources.",
    ),
    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------
    20: (
        RiskLevel.HIGH,
        "FTP active-mode data channel transmits file content in plaintext "
        "and is associated with the insecure FTP control protocol.",
        "Replace FTP with SFTP (SSH file transfer) or FTPS. "
        "If FTP must remain, restrict source IPs strictly and enable logging.",
    ),
    21: (
        RiskLevel.HIGH,
        "FTP transmits credentials and file data in plaintext and is "
        "commonly targeted by credential-brute-force attacks.",
        "Replace FTP with SFTP or FTPS. "
        "If FTP cannot be eliminated, restrict access by source IP and "
        "enforce strong credentials with account lockout policies.",
    ),
    69: (
        RiskLevel.HIGH,
        "TFTP has no authentication mechanism whatsoever; any host that can "
        "reach this port can read or write files.",
        "Disable TFTP unless it is absolutely required (e.g. PXE boot on an "
        "isolated network). Restrict to a dedicated VLAN and block externally.",
    ),
    115: (
        RiskLevel.MEDIUM,
        "SFTP (Simple File Transfer Protocol, port 115) is a legacy protocol "
        "that offers only minimal security and is rarely needed today.",
        "Confirm whether this port is genuinely in use. "
        "If so, migrate to SSH-based SFTP (TCP 22) which provides strong "
        "encryption and authentication.",
    ),
    989: (
        RiskLevel.LOW,
        "FTPS data channel is the TLS-encrypted equivalent of the FTP data "
        "channel, significantly reducing interception risk.",
        "Ensure the server enforces TLS 1.2 or higher and that certificate "
        "validation is enabled on clients.",
    ),
    990: (
        RiskLevel.LOW,
        "FTPS control channel encrypts FTP credentials and commands using "
        "TLS, which addresses FTP's core plaintext exposure.",
        "Ensure the server enforces TLS 1.2 or higher and disables fallback "
        "to unencrypted FTP.",
    ),
    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------
    25: (
        RiskLevel.MEDIUM,
        "SMTP on port 25 is used for server-to-server mail relay and may "
        "accept unauthenticated connections, making it a target for spam relay "
        "if misconfigured.",
        "Restrict inbound SMTP to known mail exchange hosts where possible. "
        "Enable STARTTLS, configure SPF/DKIM/DMARC, and audit relay permissions.",
    ),
    465: (
        RiskLevel.LOW,
        "SMTPS (implicit TLS on port 465) encrypts the mail submission "
        "channel from client to server.",
        "Ensure TLS 1.2 or higher is enforced and that weak cipher suites "
        "are disabled on the mail server.",
    ),
    587: (
        RiskLevel.MEDIUM,
        "SMTP submission on port 587 should require STARTTLS and "
        "authenticated login, but misconfigurations can expose it as an open "
        "relay.",
        "Verify that SMTP AUTH is required and that open relay is disabled. "
        "Restrict access to authenticated users only and enforce STARTTLS.",
    ),
    110: (
        RiskLevel.MEDIUM,
        "POP3 transmits email credentials and message content in plaintext "
        "unless STARTTLS is negotiated.",
        "Migrate users to POP3S (port 995) or IMAPS (port 993). "
        "If port 110 must remain, enforce STARTTLS and block non-TLS sessions.",
    ),
    995: (
        RiskLevel.LOW,
        "POP3S provides POP3 access over TLS, protecting credentials and "
        "message content in transit.",
        "Confirm TLS 1.2 or higher is enforced and that unencrypted POP3 "
        "(port 110) is disabled if not required.",
    ),
    143: (
        RiskLevel.MEDIUM,
        "IMAP transmits credentials and email content in plaintext unless "
        "STARTTLS is negotiated.",
        "Migrate to IMAPS (port 993) or enforce STARTTLS on port 143 and "
        "block plaintext sessions.",
    ),
    993: (
        RiskLevel.LOW,
        "IMAPS provides IMAP access over TLS, protecting credentials and "
        "mailbox content in transit.",
        "Confirm TLS 1.2 or higher is required and that plaintext IMAP "
        "(port 143) is disabled or STARTTLS-only.",
    ),
    # ------------------------------------------------------------------
    # DNS & directory
    # ------------------------------------------------------------------
    53: (
        RiskLevel.MEDIUM,
        "An open DNS port may be queried by any host; if recursion is "
        "enabled it can be abused for amplification attacks or information "
        "gathering.",
        "Disable recursive resolution for external clients. "
        "Restrict zone transfers (AXFR) to authorised secondaries only and "
        "consider DNS rate limiting.",
    ),
    389: (
        RiskLevel.MEDIUM,
        "LDAP transmits directory queries and bind credentials in plaintext "
        "unless STARTTLS is used.",
        "Enforce STARTTLS or migrate binds to LDAPS (port 636). "
        "Restrict access to internal hosts and service accounts only.",
    ),
    636: (
        RiskLevel.LOW,
        "LDAPS encrypts directory access over TLS, protecting credentials "
        "and query results.",
        "Ensure TLS 1.2 or higher is required and that anonymous binds are "
        "disabled if not needed.",
    ),
    3268: (
        RiskLevel.MEDIUM,
        "The Active Directory Global Catalog port exposes the full AD forest "
        "schema and user data over an unencrypted LDAP connection.",
        "Restrict access to internal trusted hosts. "
        "Use port 3269 (LDAPS Global Catalog) for encrypted access and "
        "disable anonymous queries.",
    ),
    3269: (
        RiskLevel.LOW,
        "The Active Directory Global Catalog over TLS encrypts forest-wide "
        "directory lookups.",
        "Restrict access to authorised internal hosts and service accounts; "
        "do not expose this port externally.",
    ),
    # ------------------------------------------------------------------
    # Network services
    # ------------------------------------------------------------------
    67: (
        RiskLevel.MEDIUM,
        "DHCP server port should only be accessible within its managed "
        "network segment; rogue DHCP responses can redirect all network "
        "traffic.",
        "Ensure DHCP is blocked at routed boundaries. "
        "Enable DHCP snooping on managed switches to prevent rogue servers.",
    ),
    68: (
        RiskLevel.MEDIUM,
        "DHCP client port exposure can facilitate rogue DHCP server attacks "
        "that redirect traffic.",
        "Block DHCP between routed segments and enable DHCP snooping on "
        "managed switching infrastructure.",
    ),
    123: (
        RiskLevel.LOW,
        "NTP is essential for time synchronisation but can be abused for "
        "amplification if the server responds to monlist queries.",
        "Disable the monlist command (restrict default noquery). "
        "Rate-limit NTP responses to external addresses.",
    ),
    161: (
        RiskLevel.HIGH,
        "SNMP can expose detailed device configuration and statistics; "
        "SNMPv1/v2c use plaintext community strings that are easily sniffed.",
        "Use SNMPv3 with authentication and encryption. "
        "Restrict access to a dedicated management network and change "
        "default community strings immediately.",
    ),
    162: (
        RiskLevel.HIGH,
        "SNMP trap receiver accepts unsolicited messages from network "
        "devices; exposure can reveal network topology and device state.",
        "Restrict SNMP trap receivers to a dedicated management VLAN. "
        "Validate trap source addresses and migrate to SNMPv3.",
    ),
    179: (
        RiskLevel.LOW,
        "BGP is the internet routing protocol and is expected on routers "
        "that participate in inter-AS routing.",
        "Ensure BGP sessions use MD5 or TCP-AO authentication. "
        "Apply route filtering and prefix limits to all BGP peers.",
    ),
    520: (
        RiskLevel.MEDIUM,
        "RIP (Routing Information Protocol) is an older, less secure routing "
        "protocol that can be manipulated to inject false routes.",
        "Replace RIP with a more secure routing protocol (OSPF or BGP) if "
        "possible. If RIP is required, restrict updates to trusted interfaces.",
    ),
    # ------------------------------------------------------------------
    # Windows / SMB / RPC
    # ------------------------------------------------------------------
    135: (
        RiskLevel.HIGH,
        "Microsoft RPC endpoint mapper is a common attack surface on Windows "
        "hosts and has historically been exploited for lateral movement.",
        "Block port 135 at the network perimeter. "
        "Restrict access to trusted internal hosts and apply current Windows "
        "security patches.",
    ),
    137: (
        RiskLevel.HIGH,
        "NetBIOS Name Service leaks hostnames and workgroup information and "
        "is not needed on modern networks.",
        "Disable NetBIOS over TCP/IP on all interfaces that do not require "
        "it, and block ports 137-139 at the firewall.",
    ),
    138: (
        RiskLevel.HIGH,
        "NetBIOS Datagram Service can leak workgroup and host information and "
        "is rarely needed on modern networks.",
        "Disable NetBIOS over TCP/IP and block ports 137-139 at the network perimeter.",
    ),
    139: (
        RiskLevel.HIGH,
        "NetBIOS Session Service underpins legacy SMB and leaks host "
        "information; it has been superseded by SMB over TCP (port 445).",
        "Disable NetBIOS over TCP/IP and block port 139 at the perimeter. "
        "Use SMB over port 445 only if file sharing is required.",
    ),
    445: (
        RiskLevel.HIGH,
        "SMB is essential for Windows file and print sharing but is a "
        "high-value lateral movement target and should never be exposed "
        "to untrusted networks.",
        "Block SMB (445) at the perimeter firewall. "
        "Enable SMB signing, disable SMBv1, and segment hosts that require "
        "file sharing onto a dedicated VLAN.",
    ),
    593: (
        RiskLevel.HIGH,
        "Microsoft RPC over HTTP can be used to tunnel RPC traffic through "
        "firewalls and is rarely needed outside tightly controlled environments.",
        "Block port 593 at the perimeter unless specifically required for "
        "Exchange or Outlook Anywhere. "
        "Restrict to authorised source IPs.",
    ),
    3389: (
        RiskLevel.HIGH,
        "RDP is a frequent target for brute-force attacks, credential "
        "stuffing, and exploitation; exposing it directly to the internet "
        "significantly increases attack surface.",
        "Place RDP behind a VPN or jump host and restrict source IPs with "
        "firewall rules. "
        "Enable Network Level Authentication (NLA) and enforce MFA.",
    ),
    5985: (
        RiskLevel.HIGH,
        "WinRM over HTTP transmits PowerShell remoting sessions without "
        "transport-layer encryption, exposing credentials and commands.",
        "Disable WinRM HTTP (5985) and use WinRM HTTPS (5986) instead. "
        "Restrict access to a management VLAN and require mutual "
        "authentication.",
    ),
    5986: (
        RiskLevel.MEDIUM,
        "WinRM over HTTPS provides encrypted PowerShell remoting but still "
        "represents a remote-management surface that should be tightly "
        "controlled.",
        "Restrict access to authorised management hosts only. "
        "Enforce certificate validation and require MFA for privileged "
        "access.",
    ),
    # ------------------------------------------------------------------
    # Databases
    # ------------------------------------------------------------------
    1433: (
        RiskLevel.HIGH,
        "Microsoft SQL Server should not be directly accessible from "
        "untrusted networks; exposed database ports are a primary target "
        "for credential attacks and data exfiltration.",
        "Place SQL Server behind a firewall and restrict access to "
        "application servers only. "
        "Disable the SA account, enforce strong passwords, and enable "
        "SQL Server auditing.",
    ),
    1434: (
        RiskLevel.HIGH,
        "The SQL Server Browser service on UDP 1434 discloses instance names "
        "and port numbers to any requester, aiding reconnaissance.",
        "Disable the SQL Server Browser service if named instances are not "
        "required externally. "
        "Block UDP 1434 at the perimeter.",
    ),
    1521: (
        RiskLevel.HIGH,
        "Oracle Database listener is a high-value target; direct exposure "
        "enables brute-force attacks against database accounts.",
        "Restrict access to the Oracle listener to application servers only "
        "via firewall rules. "
        "Use Oracle Connection Manager or a VPN for remote DBA access.",
    ),
    3306: (
        RiskLevel.HIGH,
        "MySQL/MariaDB should only be reachable by application servers; "
        "internet-facing database ports are a leading cause of data "
        "breaches.",
        "Bind MySQL to localhost or a private interface. "
        "Enforce strong passwords, remove anonymous accounts, and use TLS "
        "for client connections.",
    ),
    5432: (
        RiskLevel.HIGH,
        "PostgreSQL exposed to untrusted networks is a significant data "
        "exfiltration risk and a target for brute-force attacks.",
        "Restrict access via pg_hba.conf and firewall rules to application "
        "hosts only. "
        "Enable SSL, use certificate authentication where possible.",
    ),
    5984: (
        RiskLevel.MEDIUM,
        "CouchDB exposes an HTTP API that, in older or default "
        "configurations, may allow unauthenticated access to databases.",
        "Enable authentication, restrict the CouchDB bind address to "
        "localhost or a private interface, and place it behind a reverse "
        "proxy with access controls.",
    ),
    6379: (
        RiskLevel.CRITICAL,
        "Redis has no authentication by default; an exposed Redis port "
        "allows any host to read, modify, or delete all cached data and "
        "can lead to remote code execution via config manipulation.",
        "Bind Redis to localhost or a private interface. "
        "Set a strong requirepass value, enable protected-mode, and never "
        "expose Redis directly to the internet.",
    ),
    7474: (
        RiskLevel.MEDIUM,
        "Neo4j's HTTP API may allow unauthenticated access to the graph "
        "database in default or misconfigured installations.",
        "Enable authentication, restrict the Neo4j bind address to trusted "
        "interfaces, and place it behind a reverse proxy or firewall.",
    ),
    9200: (
        RiskLevel.CRITICAL,
        "Elasticsearch's HTTP API is unauthenticated in default "
        "configurations; any host can read, modify, or delete all indexed "
        "data.",
        "Enable Elasticsearch security (X-Pack) or a compatible auth "
        "plugin. "
        "Bind to localhost or a private interface and block this port at "
        "the perimeter immediately.",
    ),
    9300: (
        RiskLevel.CRITICAL,
        "The Elasticsearch cluster transport port allows nodes to join the "
        "cluster with no authentication by default, enabling full data "
        "access.",
        "Block port 9300 at the perimeter and restrict it to known cluster "
        "node IPs. "
        "Enable TLS on the transport layer via Elasticsearch security "
        "settings.",
    ),
    27017: (
        RiskLevel.CRITICAL,
        "MongoDB has no authentication enabled in some default "
        "configurations; an exposed port grants full read/write access to "
        "all databases.",
        "Enable MongoDB authentication immediately, bind to a private "
        "interface, and block this port at the perimeter. "
        "Use TLS for all client connections.",
    ),
    27018: (
        RiskLevel.HIGH,
        "MongoDB shard server port should only be reachable by cluster "
        "members; direct exposure risks full data access.",
        "Restrict port 27018 to trusted cluster nodes via firewall rules "
        "and enable authentication across the shard cluster.",
    ),
    27019: (
        RiskLevel.HIGH,
        "MongoDB config server port should only be reachable by cluster "
        "members; exposure can compromise the entire sharded cluster.",
        "Restrict port 27019 to trusted cluster nodes and verify that "
        "authentication is enforced on the config server.",
    ),
    # ------------------------------------------------------------------
    # Message brokers / queues
    # ------------------------------------------------------------------
    4369: (
        RiskLevel.HIGH,
        "EPMD (Erlang Port Mapper Daemon) discloses the ports used by "
        "Erlang nodes (RabbitMQ, CouchDB, etc.) and can be used to "
        "facilitate inter-node attacks.",
        "Block port 4369 at the perimeter. "
        "Restrict access to trusted cluster nodes only via firewall rules "
        "and use Erlang distribution cookies with high entropy.",
    ),
    5671: (
        RiskLevel.LOW,
        "AMQPS provides AMQP messaging over TLS, protecting credentials and "
        "message content in transit.",
        "Ensure TLS 1.2 or higher is required and that virtual host "
        "permissions are configured with least privilege.",
    ),
    5672: (
        RiskLevel.MEDIUM,
        "AMQP without TLS transmits credentials and message content in "
        "plaintext; exposure to untrusted networks enables interception.",
        "Migrate to AMQPS (port 5671) for encrypted messaging. "
        "Restrict access to authorised application hosts via firewall rules.",
    ),
    9092: (
        RiskLevel.MEDIUM,
        "Apache Kafka brokers may lack authentication and encryption in "
        "default configurations, exposing message streams to any connected "
        "client.",
        "Enable SASL authentication and TLS encryption on Kafka listeners. "
        "Restrict broker access to trusted producer and consumer hosts.",
    ),
    61613: (
        RiskLevel.MEDIUM,
        "STOMP is a text-based messaging protocol that may transmit "
        "credentials and messages in plaintext if TLS is not configured.",
        "Use STOMP over TLS (port 61614) instead, and restrict access to "
        "authorised messaging clients.",
    ),
    61614: (
        RiskLevel.LOW,
        "STOMP over TLS encrypts messaging traffic, reducing interception "
        "risk compared to plaintext STOMP.",
        "Ensure TLS 1.2 or higher is required and that broker authentication "
        "is enabled.",
    ),
    61616: (
        RiskLevel.MEDIUM,
        "ActiveMQ broker port may accept connections without authentication "
        "in default configurations, exposing message queues and topics.",
        "Enable ActiveMQ authentication and authorisation. "
        "Restrict access to authorised application hosts and apply current "
        "ActiveMQ patches.",
    ),
    # ------------------------------------------------------------------
    # VPN / tunnelling
    # ------------------------------------------------------------------
    500: (
        RiskLevel.LOW,
        "IKE (Internet Key Exchange) is the standard negotiation protocol "
        "for IPsec VPNs and is expected on VPN gateway interfaces.",
        "Ensure the IKE implementation is patched and that weak proposals "
        "(DES, MD5) are disabled. "
        "Use IKEv2 where supported.",
    ),
    1194: (
        RiskLevel.LOW,
        "OpenVPN is a widely used, well-regarded VPN protocol when properly "
        "configured.",
        "Keep OpenVPN updated, use TLS 1.2 or higher, enable "
        "tls-auth/tls-crypt, and restrict access to authorised client "
        "certificates.",
    ),
    1701: (
        RiskLevel.MEDIUM,
        "L2TP alone provides no encryption; it is typically paired with "
        "IPsec, but misconfiguration can leave tunnels unprotected.",
        "Confirm that L2TP is used exclusively with IPsec. "
        "Consider migrating to IKEv2/IPsec or WireGuard for stronger "
        "security guarantees.",
    ),
    1723: (
        RiskLevel.MEDIUM,
        "PPTP uses MS-CHAPv2 which is cryptographically broken; captured "
        "handshakes can be brute-forced offline.",
        "Replace PPTP with a modern VPN protocol such as IKEv2/IPsec, "
        "OpenVPN, or WireGuard.",
    ),
    4500: (
        RiskLevel.LOW,
        "IPsec NAT traversal (UDP 4500) is expected on VPN gateways that "
        "serve clients behind NAT devices.",
        "Ensure the IKE/IPsec stack is up to date and that only strong "
        "cipher suites and IKEv2 are used.",
    ),
    51820: (
        RiskLevel.LOW,
        "WireGuard is a modern, audited VPN protocol with a minimal attack "
        "surface; port 51820 is its conventional default.",
        "Keep WireGuard updated, rotate peer keys periodically, and restrict "
        "the allowed peers list to known public keys.",
    ),
    # ------------------------------------------------------------------
    # Monitoring / management (SNMP / IPMI / VNC)
    # ------------------------------------------------------------------
    # 161 already defined under Network services above
    199: (
        RiskLevel.MEDIUM,
        "SMUX (SNMP Unix Multiplexer) exposes sub-agent data through SNMP "
        "and may leak system information.",
        "Restrict port 199 to the local management network. "
        "Prefer SNMPv3 for all SNMP communication.",
    ),
    623: (
        RiskLevel.HIGH,
        "IPMI/BMC (Intelligent Platform Management Interface) has a history "
        "of serious security vulnerabilities and exposes out-of-band "
        "hardware control.",
        "Isolate IPMI on a dedicated, air-gapped management VLAN. "
        "Change default credentials, apply firmware updates, and never "
        "expose IPMI to the internet.",
    ),
    5900: (
        RiskLevel.HIGH,
        "VNC provides graphical remote access with historically weak "
        "authentication; many deployments use short, easily guessed "
        "passwords.",
        "Place VNC behind a VPN or SSH tunnel. "
        "Use strong, unique VNC passwords and restrict access by source IP "
        "via firewall rules.",
    ),
    5901: (
        RiskLevel.HIGH,
        "VNC display :1 carries the same risks as port 5900: graphical "
        "remote access with weak authentication in many deployments.",
        "Place VNC behind a VPN or SSH tunnel and restrict access to "
        "trusted source addresses.",
    ),
    5902: (
        RiskLevel.HIGH,
        "VNC display :2 carries the same risks as ports 5900/5901: "
        "graphical remote access that is frequently protected only by a "
        "short password.",
        "Place VNC behind a VPN or SSH tunnel and restrict access to "
        "trusted source addresses.",
    ),
    # ------------------------------------------------------------------
    # Containers / orchestration
    # ------------------------------------------------------------------
    2375: (
        RiskLevel.CRITICAL,
        "The unauthenticated Docker daemon API grants full control of the "
        "container runtime, including the ability to mount host filesystems "
        "and escape to root on the host.",
        "Disable the unauthenticated Docker API immediately. "
        "If remote access is required, use TLS mutual authentication on "
        "port 2376 and restrict access to trusted hosts.",
    ),
    2376: (
        RiskLevel.LOW,
        "Docker daemon over TLS provides authenticated and encrypted remote "
        "API access, significantly reducing exposure risk.",
        "Verify that client certificate authentication is correctly "
        "configured and that the CA key is stored securely.",
    ),
    2379: (
        RiskLevel.MEDIUM,
        "etcd stores Kubernetes cluster state including secrets; direct "
        "exposure of the client port can compromise the entire cluster.",
        "Restrict etcd access to the Kubernetes control plane nodes only. "
        "Enable TLS mutual authentication on all etcd endpoints.",
    ),
    2380: (
        RiskLevel.MEDIUM,
        "The etcd peer port is used for cluster replication and should never "
        "be accessible outside the control plane network.",
        "Block port 2380 at the firewall and restrict it to etcd peer IPs "
        "only. Enable TLS peer authentication.",
    ),
    6443: (
        RiskLevel.LOW,
        "The Kubernetes API server (HTTPS) is the intended management "
        "endpoint for the cluster and uses TLS and RBAC.",
        "Ensure RBAC is enforced, audit logging is enabled, and access is "
        "restricted to authorised users and CI/CD systems. "
        "Do not expose this port to the public internet unnecessarily.",
    ),
    10250: (
        RiskLevel.MEDIUM,
        "The Kubelet API (port 10250) provides node-level container "
        "management and has been abused in the past for privilege escalation "
        "when improperly secured.",
        "Ensure Kubelet authentication and authorisation are enabled "
        "(--anonymous-auth=false). "
        "Restrict access to the control plane and monitoring systems only.",
    ),
    10255: (
        RiskLevel.CRITICAL,
        "The Kubelet read-only API (port 10255) exposes pod and node "
        "metadata with no authentication, leaking workload details and "
        "internal cluster information.",
        "Disable the Kubelet read-only port by setting "
        "--read-only-port=0 in the Kubelet configuration. "
        "Verify the change across all worker nodes.",
    ),
    # ------------------------------------------------------------------
    # Miscellaneous / legacy well-known ports
    # ------------------------------------------------------------------
    7: (
        RiskLevel.INFO,
        "The Echo service simply reflects incoming data and has no practical "
        "use on modern systems.",
        "Disable the Echo service if enabled. "
        "It should not be running on any production host.",
    ),
    9: (
        RiskLevel.INFO,
        "The Discard service discards all data sent to it and is not needed "
        "on modern systems (Wake-on-LAN uses UDP 9, not TCP).",
        "Disable the Discard service if it is running. "
        "It has no legitimate use on production hosts.",
    ),
    13: (
        RiskLevel.INFO,
        "The Daytime protocol returns the current time as a human-readable "
        "string; it is obsolete and has no use on modern systems.",
        "Disable the Daytime service. Use NTP (port 123) for time synchronisation.",
    ),
    19: (
        RiskLevel.CRITICAL,
        "The Character Generator (Chargen) service can be used to amplify "
        "DDoS attacks by generating endless streams of data in response to "
        "a spoofed source address.",
        "Disable Chargen immediately. "
        "There is no legitimate use case for this service on any modern host.",
    ),
    37: (
        RiskLevel.INFO,
        "The Time protocol (RFC 868) is an obsolete time synchronisation "
        "service that has been superseded by NTP.",
        "Disable the Time service. Use NTP (port 123) for time synchronisation.",
    ),
    79: (
        RiskLevel.HIGH,
        "The Finger protocol discloses user account information including "
        "login names, full names, and last-login times, aiding "
        "reconnaissance.",
        "Disable the Finger daemon. "
        "This service has no legitimate use on modern systems and should "
        "not be exposed to any untrusted network.",
    ),
    111: (
        RiskLevel.HIGH,
        "RPCbind (portmapper) discloses the ports used by all registered "
        "RPC services and can be used to enumerate NFS and NIS "
        "infrastructure.",
        "Block port 111 at the perimeter firewall. "
        "If NFS is required, restrict it to trusted internal subnets only.",
    ),
    119: (
        RiskLevel.INFO,
        "NNTP (Usenet) is a legacy news transfer protocol rarely used on "
        "private networks; its presence may indicate an unintended service.",
        "Verify whether NNTP is intentionally running. "
        "If not, disable it and block the port.",
    ),
    194: (
        RiskLevel.INFO,
        "IRC on port 194 is the IANA-assigned port but is rarely used; most "
        "IRC activity occurs on port 6667 or 6697.",
        "Verify whether IRC is an expected service on this host. "
        "IRC should only be accessible from authorised clients.",
    ),
    6667: (
        RiskLevel.MEDIUM,
        "Unencrypted IRC transmits messages and credentials in plaintext; "
        "IRC servers are also frequently used as command-and-control "
        "channels by malware.",
        "Migrate to IRC over TLS (port 6697) and restrict access to "
        "authorised users. "
        "Investigate if this port is unexpected on the host.",
    ),
    6697: (
        RiskLevel.LOW,
        "IRC over TLS encrypts chat traffic, reducing interception risk "
        "compared to plaintext IRC.",
        "Restrict access to authorised users and ensure the TLS "
        "certificate is valid and up to date.",
    ),
    1080: (
        RiskLevel.HIGH,
        "An open SOCKS proxy can be used by any host to route traffic "
        "through the server, potentially bypassing firewalls and concealing "
        "the true origin of traffic.",
        "Disable the SOCKS proxy if it is unintended. "
        "If a proxy is required, restrict access to authorised clients with "
        "strong authentication.",
    ),
    3128: (
        RiskLevel.MEDIUM,
        "Squid or another HTTP proxy on port 3128 may allow arbitrary hosts "
        "to proxy traffic through the server if access controls are not "
        "configured.",
        "Restrict proxy access to authorised internal clients only via ACLs. "
        "Disable caching of sensitive content and enable access logging.",
    ),
    8123: (
        RiskLevel.LOW,
        "Home Assistant's web interface is a smart-home management panel; "
        "direct internet exposure increases the risk of unauthorised "
        "device control.",
        "Place Home Assistant behind a VPN or reverse proxy with strong "
        "authentication rather than exposing it directly. "
        "Enable MFA in Home Assistant settings.",
    ),
    # ------------------------------------------------------------------
    # Web servers and development servers
    # ------------------------------------------------------------------
    80: (
        RiskLevel.MEDIUM,
        "HTTP transmits all data in plaintext; clients and servers are "
        "visible to network observers and vulnerable to interception.",
        "Redirect all HTTP traffic to HTTPS and implement HSTS. "
        "Keep the web server and its dependencies patched.",
    ),
    443: (
        RiskLevel.LOW,
        "HTTPS is the expected and recommended way to serve web content; "
        "its presence alone does not indicate a problem.",
        "Ensure TLS 1.2 or higher is enforced, weak cipher suites are "
        "disabled, and the certificate is valid and renewed before expiry.",
    ),
    8080: (
        RiskLevel.MEDIUM,
        "HTTP on an alternate port often indicates a development server, "
        "proxy, or admin panel that may lack the hardening applied to the "
        "primary web server.",
        "Confirm this port is intentional and apply the same security "
        "controls as the primary web service. "
        "Migrate to HTTPS if this endpoint serves sensitive data.",
    ),
    8443: (
        RiskLevel.LOW,
        "HTTPS on an alternate port is commonly used for management "
        "interfaces or secondary web services.",
        "Ensure TLS 1.2 or higher is enforced and that access to this port "
        "is restricted if it serves an administrative interface.",
    ),
    8008: (
        RiskLevel.MEDIUM,
        "HTTP on port 8008 is often a secondary or legacy web service that "
        "may not receive the same patch and hardening attention as the "
        "primary server.",
        "Confirm this service is intentional, apply security headers, "
        "and migrate to HTTPS if sensitive data is served.",
    ),
    3000: (
        RiskLevel.MEDIUM,
        "Port 3000 is a common default for development web frameworks "
        "(Node.js/Express, Rails, etc.) and is unlikely to be hardened for "
        "production exposure.",
        "Verify this is not an unintended development server. "
        "If it must be accessible, place it behind a reverse proxy with "
        "HTTPS and access controls.",
    ),
    5000: (
        RiskLevel.MEDIUM,
        "Port 5000 is the default for Flask and several other development "
        "servers; it is typically not hardened for internet-facing use.",
        "Confirm this is an intended production service. "
        "If so, place it behind a reverse proxy with HTTPS; do not expose "
        "debug mode to untrusted networks.",
    ),
    8888: (
        RiskLevel.MEDIUM,
        "Port 8888 is the default for Jupyter Notebook, which provides "
        "arbitrary code execution via the browser; internet exposure is "
        "extremely dangerous.",
        "Do not expose Jupyter Notebook to the internet. "
        "Use SSH tunnelling or a VPN for remote access and enable "
        "token/password authentication.",
    ),
}


# ---------------------------------------------------------------------------
# assess()
# ---------------------------------------------------------------------------


def assess(
    port: int,
    service_name: str,
    banner_raw: str | None = None,
) -> RiskAssessment:
    """
    Return a RiskAssessment for the given port.

    Parameters
    ----------
    port:
        The TCP port number being assessed.
    service_name:
        The inferred service name (e.g. ``"SSH"``, ``"HTTP"``, ``"unknown"``).
    banner_raw:
        Optional sanitized banner string captured from the port.  When
        provided it may be used to add context to the reason or recommendation.

    Returns
    -------
    RiskAssessment
        Populated with level, reason, recommendation, and the standard
        DISCLAIMER.
    """
    banner = (banner_raw or "").lower()

    # ------------------------------------------------------------------
    # 1. Look up base rule
    # ------------------------------------------------------------------
    if port in _PORT_RULES:
        level, reason, recommendation = _PORT_RULES[port]

        # --------------------------------------------------------------
        # 2. Banner-based context adjustments
        # --------------------------------------------------------------

        # FTP (21) — note specific server software if visible in banner
        if port == 21 and banner_raw:
            if "vsftpd" in banner:
                reason = (
                    f"FTP server identified as vsftpd from banner. "
                    "FTP transmits credentials in plaintext and is a "
                    "frequent brute-force target."
                )
            elif "proftpd" in banner:
                reason = (
                    f"FTP server identified as ProFTPD from banner. "
                    "FTP transmits credentials in plaintext and is a "
                    "frequent brute-force target."
                )

        # SSH (22) — note software version if present in banner
        elif port == 22 and banner_raw:
            reason = (
                f"SSH service identified from banner ({banner_raw[:80]}). "
                "SSH is a frequent target for brute-force and credential "
                "attacks; version information aids targeted reconnaissance."
            )

        # HTTP / HTTP-alt (80, 8080) — note server software if revealed
        elif port in (80, 8080) and banner_raw:
            reason = (
                f"HTTP service identified from banner ({banner_raw[:80]}). "
                "HTTP transmits all data in plaintext and banner disclosure "
                "reveals server software that may narrow the attack surface."
            )

        # Docker unauthenticated (2375) — any banner confirms the API is live
        elif port == 2375 and banner_raw:
            level = RiskLevel.CRITICAL
            reason = (
                "Unauthenticated Docker API confirmed by banner. "
                "Full container runtime control, including host filesystem "
                "access, is available to any host that can reach this port."
            )
            recommendation = (
                "Shut down the unauthenticated Docker API immediately. "
                "If remote access is required, use TLS mutual authentication "
                "on port 2376 and restrict access to trusted hosts."
            )

        return RiskAssessment(
            port=port,
            service=service_name,
            level=level,
            reason=reason,
            recommendation=recommendation,
            disclaimer=DISCLAIMER,
        )

    # ------------------------------------------------------------------
    # 3. Port not in the rules table
    # ------------------------------------------------------------------
    if service_name.lower() != "unknown":
        return RiskAssessment(
            port=port,
            service=service_name,
            level=RiskLevel.MEDIUM,
            reason=(
                f"Known service ({service_name}) detected on a non-standard "
                "port; this may indicate deliberate port obfuscation or a "
                "misconfiguration."
            ),
            recommendation=(
                "Verify whether this service is intentionally running on a "
                "non-standard port. "
                "Apply the same hardening controls appropriate for the "
                "service regardless of port number."
            ),
            disclaimer=DISCLAIMER,
        )

    return RiskAssessment(
        port=port,
        service=service_name,
        level=RiskLevel.LOW,
        reason=(
            f"Unrecognised service on port {port}; the service identity "
            "could not be determined from port conventions alone."
        ),
        recommendation=(
            "Investigate what is listening on this port. "
            "Capture a banner, check the process listening (e.g. with "
            "`ss -tlnp` or `netstat`), and close the port if it is not "
            "intentionally exposed."
        ),
        disclaimer=DISCLAIMER,
    )


# ---------------------------------------------------------------------------
# assess_results()
# ---------------------------------------------------------------------------


def assess_results(results: list) -> list[RiskAssessment]:
    """
    Assess all open ports in a list of PortResult objects.

    Only ports with ``status == "open"`` are assessed; closed or unreachable
    ports are silently skipped.

    Parameters
    ----------
    results:
        A list of objects that expose ``.port`` (int), ``.status`` (str),
        ``.service_name`` (str), and ``.banner`` (``BannerResult | None``)
        attributes — matching the ``PortResult`` type from ``models.py``.

    Returns
    -------
    list[RiskAssessment]
        One entry per open port, in the same order as the input list.
    """
    assessments: list[RiskAssessment] = []
    for result in results:
        if result.status != "open":
            continue
        banner_raw: str | None = None
        if result.banner is not None:
            banner_raw = result.banner.raw or None
        assessments.append(assess(result.port, result.service_name, banner_raw))
    return assessments
