# Palo Alto Networks Firewall — Complete Training Notes
> Structured for 25-video lecture series | GitHub Repository Edition  
> Suitable for PCNSA / PCNSE exam preparation and hands-on lab learning

---

## Table of Contents

1. [Introduction to Palo Alto Networks & NGFW Concepts](#1-introduction-to-palo-alto-networks--ngfw-concepts)
2. [Architecture of PAN-OS](#2-architecture-of-pan-os)
3. [Initial Setup & Management Access](#3-initial-setup--management-access)
4. [Interfaces, Zones & VLANs](#4-interfaces-zones--vlans)
5. [Security Policies (Firewall Rules)](#5-security-policies-firewall-rules)
6. [NAT — Network Address Translation](#6-nat--network-address-translation)
7. [App-ID — Application Identification](#7-app-id--application-identification)
8. [User-ID — User Identification](#8-user-id--user-identification)
9. [Content-ID — Threat Prevention](#9-content-id--threat-prevention)
10. [SSL/TLS Decryption](#10-ssltls-decryption)
11. [URL Filtering](#11-url-filtering)
12. [VPN — Site-to-Site & GlobalProtect](#12-vpn--site-to-site--globalprotect)
13. [High Availability (HA)](#13-high-availability-ha)
14. [Panorama — Centralized Management](#14-panorama--centralized-management)
15. [Logging, Monitoring & SIEM Integration](#15-logging-monitoring--siem-integration)
16. [Routing on Palo Alto Firewall](#16-routing-on-palo-alto-firewall)
17. [QoS & Policy Based Forwarding](#17-qos--policy-based-forwarding)
18. [Wildfire — Cloud-Based Malware Analysis](#18-wildfire--cloud-based-malware-analysis)
19. [Zone Protection & DoS Policies](#19-zone-protection--dos-policies)
20. [Certificates & PKI on PAN-OS](#20-certificates--pki-on-pan-os)
21. [Troubleshooting & CLI Commands](#21-troubleshooting--cli-commands)
22. [Labs Summary — Quick Reference](#22-labs-summary--quick-reference)
23. [Key Terms Glossary](#23-key-terms-glossary)

---

## 1. Introduction to Palo Alto Networks & NGFW Concepts

### What is a Next-Generation Firewall (NGFW)?
A traditional firewall controls traffic based on IP address and port number only.  
A **Next-Generation Firewall (NGFW)** adds:
- Application awareness (knows *what* the traffic is, not just *where* it came from)
- User awareness (knows *who* is sending the traffic)
- Content inspection (scans the traffic payload for threats, malware, sensitive data)

### Why Palo Alto?
- Palo Alto Networks invented the first true NGFW in 2007
- PAN-OS is the OS that runs on all Palo Alto hardware and virtual firewalls
- Leader in Gartner Magic Quadrant for Network Firewalls for 10+ consecutive years

### Palo Alto Product Lines

| Category | Products |
|---|---|
| Hardware NGFWs | PA-400, PA-800, PA-3200, PA-5200, PA-7000 Series |
| Virtual NGFWs | VM-50, VM-100, VM-300, VM-500, VM-700, VM-1000-HV |
| Cloud NGFWs | CN-Series (Kubernetes), VM-Series on AWS/Azure/GCP |
| Centralized Mgmt | Panorama (M-100, M-200, M-500, M-700, Virtual) |
| SD-WAN | Prisma SD-WAN (formerly CloudGenix) |
| SASE | Prisma Access |

### Palo Alto Certifications Ladder
```
PCCET  →  PCNSA  →  PCNSE
(Entry)   (Associate) (Expert)
```

---

## 2. Architecture of PAN-OS

### The Three Core Engines of PAN-OS
PAN-OS processes every packet through three identification technologies in a single pass:

```
Traffic enters firewall
        ↓
  [ App-ID Engine ]       → Identifies the application (not just port)
        ↓
  [ User-ID Engine ]      → Identifies the user behind the IP address
        ↓
  [ Content-ID Engine ]   → Scans content for threats, files, URLs
        ↓
Security Policy Decision  → Allow / Deny / Inspect
```

### Single-Pass Parallel Processing (SP3)
- All three engines run in **parallel**, not sequentially
- This means **no performance penalty** for enabling all features
- Traditional firewalls run engines sequentially — slower and resource-heavy

### Management Plane vs Data Plane

| Plane | Handles | Examples |
|---|---|---|
| Management Plane | Administrative functions | CLI, WebGUI, Panorama, Logging |
| Data Plane | Traffic forwarding | Firewall policy, NAT, decryption, routing |

These are **physically separated** on hardware models — a crash in management does NOT affect traffic forwarding.

### PAN-OS Key Components

| Component | Role |
|---|---|
| Security Policy | Core rules — what traffic is allowed |
| App-ID | Application signature database (updated daily) |
| Threat Prevention | IPS/IDS signatures |
| WildFire | Cloud sandbox for unknown files |
| URL Filtering | PAN-DB (Palo Alto's own URL database) |
| GlobalProtect | Remote access VPN client |

---

## 3. Initial Setup & Management Access

### Default Credentials
| Parameter | Default Value |
|---|---|
| Management IP | 192.168.1.1/24 |
| Username | admin |
| Password | admin |
| HTTPS access | https://192.168.1.1 |

> ⚠️ Always change the default password on first login.

### Management Access Methods

1. **Web GUI (HTTPS)** — Most common for day-to-day management
2. **CLI (SSH or Console)** — Best for scripting, bulk changes, troubleshooting
3. **Panorama** — Centralized management for multiple firewalls
4. **REST API / XML API** — Automation (Terraform, Ansible, Python)

### CLI Modes
```bash
>   # Operational Mode  — show commands, ping, traceroute, clear
#   # Configuration Mode — set, delete, edit, commit
```

### Essential First-Boot Steps
```bash
# Step 1: Set hostname
set deviceconfig system hostname PA-LAB-FW

# Step 2: Set DNS
set deviceconfig system dns-setting servers primary 8.8.8.8
set deviceconfig system dns-setting servers secondary 8.8.4.4

# Step 3: Set NTP
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address pool.ntp.org

# Step 4: Set management interface IP
set deviceconfig system ip-address 10.0.0.1 netmask 255.255.255.0 default-gateway 10.0.0.254

# Step 5: Commit (MANDATORY after every change)
commit
```

> 🔑 **Key concept:** In PAN-OS, NO change takes effect until you run `commit`. This is called a **candidate configuration** model.

### Candidate vs Running Configuration
- **Candidate config** — what you are editing right now (not live)
- **Running config** — what is actively enforcing traffic
- `commit` = push candidate → running
- `revert` = discard candidate changes

---

## 4. Interfaces, Zones & VLANs

### Interface Types in PAN-OS

| Interface Type | Use Case |
|---|---|
| Layer 3 | Routed interfaces — most common. Has an IP address |
| Layer 2 | Switched interfaces — bridges traffic |
| Virtual Wire (vwire) | Transparent bump-in-the-wire — no IP, no routing change |
| Tap | Passive monitoring only — receives a copy of traffic |
| HA | Dedicated to High Availability heartbeat/sync |
| Management | Out-of-band management (always separate) |
| Loopback | Virtual interfaces for management, VPN, DNS proxy |
| Tunnel | For VPN tunnels |
| VLAN | Sub-interfaces for 802.1Q VLAN tagging |

### What is a Security Zone?
- A **zone** is a logical grouping of interfaces
- Traffic between zones requires a **security policy** to pass
- Traffic within the same zone is allowed by default (intrazone)

### Default Zones
```
Untrust  →  Internet-facing (low trust)
Trust    →  Internal LAN (high trust)
DMZ      →  Servers accessible from outside
```

### Zone Types
| Zone Type | Description |
|---|---|
| Layer 3 | For L3 interfaces (most common) |
| Layer 2 | For L2 interfaces |
| Virtual Wire | For vwire interfaces |
| Tap | For tap interfaces |
| Tunnel | For VPN tunnels |
| External | For communication between vsys (virtual systems) |

### Sub-interfaces (VLANs)
```
ethernet1/1         # Physical interface (trunk port)
ethernet1/1.10      # Sub-interface for VLAN 10
ethernet1/1.20      # Sub-interface for VLAN 20
```
Each sub-interface can be in a **different zone** — this is how to segment VLANs with firewall policy.

### Virtual Routers
- A Palo Alto firewall has its own **virtual router** (like a routing table)
- You can have **multiple virtual routers** (vsys isolation)
- Default virtual router is called `default`

---

## 5. Security Policies (Firewall Rules)

### Security Policy Fundamentals
This is the **heart of the firewall**. Every connection is matched against policies **top to bottom**. First match wins.

### Policy Match Criteria

| Field | Description |
|---|---|
| Source Zone | Where traffic comes from |
| Destination Zone | Where traffic is going |
| Source Address | Source IP / address object |
| Destination Address | Destination IP / address object |
| Application | App-ID identified application |
| Service | Port/Protocol (usually use "application-default") |
| User | User-ID matched user (optional) |
| Action | Allow / Deny / Drop / Reset |

### Rule Types

| Type | Behavior |
|---|---|
| Universal | Matches both interzone and intrazone (default) |
| Intrazone | Only matches traffic within the same zone |
| Interzone | Only matches traffic between different zones |

### Implicit Default Rules
At the bottom of every policy table (not visible but active):
- **Allow intrazone** — traffic within the same zone is allowed
- **Deny interzone** — traffic between zones is denied

> ✅ Best practice: Add an explicit "deny all" rule at the bottom with logging enabled so you can see what's being blocked.

### Address Objects
Instead of typing IPs everywhere, create reusable objects:
```
IP Netmask:   10.10.10.0/24
IP Range:     10.10.10.1 - 10.10.10.50
FQDN:         server.example.com   (auto-resolved by firewall)
```

### Service Objects vs Application-Default
- **application-default** — only allows the app on the ports Palo Alto knows it uses (e.g., HTTP on 80/443). **Always use this!**
- **any** — allows the app on ANY port (security risk)

### Security Profile Groups
After allowing traffic, attach profiles to inspect content:
```
Antivirus Profile       → scan for known malware
Vulnerability Profile   → block IPS/IDS signatures
Anti-Spyware Profile    → block C2/botnet traffic
URL Filtering Profile   → block bad websites
File Blocking Profile   → block/alert on file types
WildFire Profile        → send unknown files to sandbox
```

---

## 6. NAT — Network Address Translation

### Types of NAT on PAN-OS

| NAT Type | Use Case |
|---|---|
| Source NAT (SNAT) | Users going to internet — translate source IP |
| Destination NAT (DNAT) | Inbound traffic — redirect to internal server |
| Bidirectional NAT | Map one public IP to one private IP both ways |
| No NAT | Explicitly disable NAT for a traffic flow |

### Source NAT — Dynamic IP and Port (DIPP)
Most common. All inside users share one public IP (like a home router).
```
Source Zone:       Trust
Destination Zone:  Untrust
Source Address:    10.10.10.0/24
Translation:       Dynamic IP and Port → interface IP of ethernet1/1
```

### Destination NAT — Port Forwarding
Used to expose internal servers (e.g., web server, RDP server):
```
Destination Zone:       Untrust
Destination Address:    203.0.113.10 (public IP)
Service:                TCP/443
Translated Address:     192.168.1.100 (private server IP)
Translated Port:        443
```

### NAT Policy Evaluation Order
```
1. NAT policy matched (pre-NAT IPs used for matching)
2. Security policy matched (also uses pre-NAT IPs for source, post-NAT for destination)
3. NAT translation applied
4. Traffic forwarded
```
> ⚠️ Common mistake: Writing security policy with post-NAT IPs. Always use **pre-NAT** IPs in security rules.

### U-Turn NAT (Hairpin NAT)
When internal users access a server using its public IP from inside the network:
```
Source Zone:           Trust
Destination Zone:      Trust
Destination Address:   203.0.113.10 (public IP)
Translated Dest:       192.168.1.100 (server's real IP)
Source Translation:    Interface IP (so return traffic comes back correctly)
```

---

## 7. App-ID — Application Identification

### What is App-ID?
- Palo Alto's **application signature database**
- Identifies 4,000+ applications regardless of port or encryption
- Updated automatically via dynamic updates

### How App-ID Works (4-Step Process)
```
Step 1: IP/Port classification     → Quick first pass (port 80 = likely web)
Step 2: Application signatures     → Decode protocol, match known patterns
Step 3: Protocol decryption        → If SSL, decrypt to inspect
Step 4: Heuristics                  → Behavioral analysis for unknown apps
```

### App-ID vs Port-Based Firewall
| Scenario | Old Firewall | Palo Alto NGFW |
|---|---|---|
| BitTorrent on port 80 | ✅ Allowed (port 80 is allowed) | ❌ Blocked (App-ID = bittorrent) |
| Skype on random port | ❌ Blocked (unknown port) | ✅ Allowed (App-ID = skype-base) |
| HTTP tunnel over DNS | ✅ Allowed | ❌ Blocked (detects tunneling) |

### App Dependencies
Some apps are built on top of other apps:
```
youtube        depends on  →  ssl, web-browsing
facebook-base  depends on  →  ssl, web-browsing
```
You must allow the **parent apps** too (or use `application-default`).

### Custom App-ID
You can create custom signatures for proprietary applications your vendor hasn't defined yet.

### Application Groups & Filters
- **Application Group** — static list of apps you bundle together
- **Application Filter** — dynamic filter based on app attributes (category, subcategory, risk, technology)

---

## 8. User-ID — User Identification

### What is User-ID?
- Maps IP addresses to **usernames**
- Allows writing security policies like: "Allow Finance team to access SAP"
- No need to manage static IP-to-user mappings manually

### User-ID Data Sources (How it learns who is at an IP)

| Source | How It Works |
|---|---|
| Active Directory (WMI) | Reads Windows Security Event Logs remotely |
| Active Directory (Agent) | Installs User-ID agent on DC |
| Syslog parsing | Parses VPN/RADIUS/DHCP syslog messages |
| Captive Portal | Forces browser login (for unmanaged devices) |
| GlobalProtect | VPN client provides user info directly |
| XML API | Custom integration via REST API |
| Terminal Server Agent | For RDP/Citrix environments (all users share 1 IP) |

### User-ID Agent
Software installed on a Windows server (usually a Domain Controller):
- Polls Windows event logs for logon/logoff events
- Sends IP-to-user mappings to the firewall
- Open-source alternative: PAN-OS built-in "agentless" polling

### Groups in Security Policy
Instead of users, add **Active Directory groups** to policies:
```
Source User: CN=Finance,OU=Groups,DC=company,DC=com
```
This dynamically includes all members of the Finance group.

### Captive Portal
For users not on domain (guests, contractors):
- Browser is redirected to a login page hosted by the firewall
- After login, their IP is mapped to their username

---

## 9. Content-ID — Threat Prevention

### What is Content-ID?
The engine that **inspects the payload** of allowed traffic for malicious content.

### Content-ID Components

#### 1. Antivirus
- Scans files and streams for known malware using signatures
- Updated daily via Dynamic Updates
- Protocols inspected: HTTP, HTTPS (with decryption), FTP, SMTP, IMAP, POP3, SMB

#### 2. Anti-Spyware
- Detects and blocks spyware, command-and-control (C2) traffic, botnets
- Blocks DNS-based C2 (DNS sinkholing)

#### 3. Vulnerability Protection (IPS)
- Detects attempts to exploit software vulnerabilities
- Covers CVEs, buffer overflows, SQL injection at network level
- Separate from antivirus — scans the method of attack, not the file itself

#### 4. File Blocking
- Block or alert on specific file types (e.g., block `.exe` downloads)
- Can block files in both upload and download directions

#### 5. Data Filtering (DLP)
- Detects sensitive data in outbound traffic
- Built-in patterns for: credit card numbers, SSNs, custom patterns
- Can generate alerts or block outbound transmission

### Security Profile — Best Practice Settings

| Profile | Recommended Action |
|---|---|
| Antivirus | Reset both (server and client) for medium/high |
| Anti-Spyware | Reset / Drop for medium, high, critical |
| Vulnerability | Reset / Drop for medium, high, critical |
| URL Filtering | Alert or block based on category |
| WildFire | Forward all unknown files |

### Threat Severity Levels
```
Critical  →  Active exploitation in the wild, system compromise likely
High      →  Remote code execution, privilege escalation
Medium    →  Information disclosure, DoS conditions
Low       →  Minor impact, local access required
Informational → No direct threat, logged for awareness
```

---

## 10. SSL/TLS Decryption

### Why Decrypt?
- 80%+ of all internet traffic is encrypted (HTTPS)
- Without decryption: App-ID, threat prevention, URL filtering are **blind** to encrypted content
- Attackers increasingly use encryption to hide malware

### Types of SSL Decryption

| Type | Use Case |
|---|---|
| SSL Forward Proxy | Decrypt outbound traffic (users browsing internet) |
| SSL Inbound Inspection | Decrypt inbound traffic to your servers |
| SSH Proxy | Inspect outbound SSH sessions |

### SSL Forward Proxy — How It Works
```
User Browser ←→ [Firewall acts as man-in-the-middle] ←→ Real Server
               ↓ Firewall has TWO separate TLS sessions ↑
         (User←→FW)                        (FW←→Server)
```
The firewall **re-signs the server certificate** using its own CA certificate.
The user's device must **trust the firewall's CA** (deployed via Group Policy).

### Decryption Profile
Controls behavior during decryption:
- Block expired certificates
- Block certificates with untrusted issuers
- Block sessions with weak algorithms (RC4, export ciphers)
- Set minimum TLS version (enforce TLS 1.2+)

### SSL Exclusions (No Decrypt List)
Some traffic should NOT be decrypted:
- Banking and healthcare websites (privacy/legal)
- Certificate-pinned apps (will break)
- URLs/categories added to "SSL Exclusion" list

---

## 11. URL Filtering

### PAN-DB — Palo Alto's URL Database
- 60+ billion URLs categorized
- Categories: social networking, gambling, malware, phishing, news, etc.
- Updated in real-time from the cloud

### URL Filtering Actions

| Action | Behavior |
|---|---|
| Allow | Permit access, no logging |
| Alert | Permit access, log it |
| Block | Deny access, show block page |
| Continue | Show warning, user can click through |
| Override | Requires admin password to proceed |
| None | No action (inherit default) |

### Custom URL Categories
Create your own lists of URLs with a specific action:
- Whitelist: always allow (e.g., your own company domain)
- Blacklist: always block (e.g., competitor sites)

### Safe Search Enforcement
- Forces Google, Bing, YouTube to strict safe search mode
- Requires SSL decryption to be active

---

## 12. VPN — Site-to-Site & GlobalProtect

### Site-to-Site VPN (IPsec)

#### IKE Phase 1 — Build the management tunnel
```
Authentication:  Pre-shared key or Certificates
Encryption:      AES-128/256
Hashing:         SHA-256/384
DH Group:        Group 14, 19, 20 (prefer 19/20 = ECC)
Mode:            Main Mode (more secure) or Aggressive Mode
```

#### IKE Phase 2 — Build the data tunnel (IPsec SA)
```
Protocol:    ESP (Encapsulating Security Payload) — encrypts data
Encryption:  AES-128/256-GCM
Hashing:     SHA-256/384
PFS:         Enable (Perfect Forward Secrecy)
```

#### VPN Configuration Steps
```
1. Create IKE Gateway  (Device > Network > Network Profiles > IKE Gateways)
2. Create IPsec Tunnel (Network > IPsec Tunnels)
3. Add Tunnel Interface to a Zone
4. Add static route for remote subnet via tunnel interface
5. Create security policy allowing tunnel zone traffic
6. Commit and test
```

### GlobalProtect — Remote Access VPN

#### Components
| Component | Role |
|---|---|
| GlobalProtect Portal | Central config server (authentication, agent config) |
| GlobalProtect Gateway | Actual VPN gateway (can be same firewall) |
| GlobalProtect Agent | Client software on user devices |
| HIP Profiles | Host Information Profile — checks device compliance |

#### Authentication Methods
- LDAP / Active Directory
- RADIUS / TACACS+
- SAML 2.0 (Azure AD, Okta, etc.)
- Client certificates

#### HIP Checks (Host Integrity Profile)
Before allowing VPN, verify:
- Antivirus is installed and up to date
- OS is patched (Windows version check)
- Disk encryption enabled
- No jailbroken/rooted device

---

## 13. High Availability (HA)

### Why HA?
- Eliminates single point of failure
- Provides automatic failover if primary firewall fails

### HA Modes

| Mode | Description |
|---|---|
| Active/Passive | One firewall active, one standby. Failover on failure. |
| Active/Active | Both firewalls pass traffic. More complex. Requires floating IPs. |

### HA Links

| Link | Purpose |
|---|---|
| HA1 | Control link — heartbeat, state sync, config sync |
| HA2 | Data link — session table sync (for stateful failover) |
| HA3 | Packet forwarding link (Active/Active only) |
| HA4 | Backup HA1 (management plane backup heartbeat) |

### HA1 Heartbeat
- Sent every 1000ms (default)
- If missed 3 times (3 seconds) → failover triggered
- Can use dedicated HA interface or management interface

### Configuration Sync
- When you commit on the active firewall, config is automatically synchronized to the passive
- Session table sync happens continuously over HA2

### Failover Triggers
- Interface goes down (link monitoring)
- Path goes down — firewall pings a remote IP (path monitoring)
- HA1 heartbeat lost

---

## 14. Panorama — Centralized Management

### What is Panorama?
- Centralized management platform for multiple Palo Alto firewalls
- Single pane of glass: manage 1000s of firewalls from one place
- Deployed as a hardware appliance (M-series) or VM

### Panorama Key Concepts

| Concept | Description |
|---|---|
| Device Group | Logical grouping of firewalls for policy management |
| Template | Configuration pushed to firewalls (interfaces, zones, routing) |
| Template Stack | Stack multiple templates — base + site-specific |
| Managed Device | A firewall registered to Panorama |
| Collector Group | Aggregates logs from multiple firewalls |

### Policy Hierarchy in Panorama
```
Panorama Pre-Rules    → Evaluated FIRST (can't be overridden by device)
     ↓
Device Local Rules    → Firewall-specific rules
     ↓
Panorama Post-Rules   → Evaluated LAST (catch-all, defaults)
```

### Push vs Commit
- **Commit to Panorama** — saves to Panorama's running config
- **Push to Devices** — sends the config out to managed firewalls

---

## 15. Logging, Monitoring & SIEM Integration

### Log Types in PAN-OS

| Log Type | What It Captures |
|---|---|
| Traffic | Every connection allowed or denied |
| Threat | Detected threats (AV, IPS, spyware) |
| URL Filtering | URL access events |
| WildFire | File submission verdicts |
| Authentication | User authentication events |
| System | Firewall system events (config changes, HA events) |
| Config | Audit trail of admin configuration changes |
| HIP Match | GlobalProtect host compliance events |

### Log Forwarding Methods

| Method | Description |
|---|---|
| Syslog | Forward to any SIEM (Splunk, QRadar, etc.) |
| SNMP Traps | Alerts to NMS |
| Email | Alert emails for specific events |
| HTTP | Webhook/REST API (custom SIEM integration) |
| Panorama | Centralized log collection |

### Log Forwarding Profile
Applied to security policies to control what gets logged:
- Log at session start (verbose)
- Log at session end (default — recommended)
- Log only on threat detected

### Splunk Integration
- Use **Palo Alto Add-on for Splunk** (free on Splunkbase)
- Sends logs via syslog in PAN-OS format
- Pre-built dashboards for threat intelligence, traffic analysis

---

## 16. Routing on Palo Alto Firewall

### Supported Routing Protocols

| Protocol | Use Case |
|---|---|
| Static Routes | Simple/small networks, VPN routes |
| OSPF | IGP for enterprise LAN/WAN |
| BGP | Internet peering, MPLS, SD-WAN |
| RIP | Legacy (avoid in new deployments) |
| PBF | Policy-Based Forwarding (route by app/user) |

### Virtual Routers
Each virtual router has its own independent routing table. Common use:
- `default` VR — connected to internet
- `internal` VR — connected to internal segments
- Route leaking between VRs requires explicit configuration

### Static Route Configuration
```bash
# Via CLI
set network virtual-router default routing-table ip static-route "default-route" \
  interface ethernet1/1 \
  nexthop ip-address 203.0.113.1 \
  destination 0.0.0.0/0

commit
```

### ECMP — Equal Cost Multi-Path
- Load balance traffic across multiple equal-cost routes
- Supported hash methods: IP Modulo, IP Hash, Weighted Round Robin

---

## 17. QoS & Policy Based Forwarding

### QoS (Quality of Service)
- Prioritize critical traffic (VoIP, video conferencing) over bulk transfers
- Applied outbound on interfaces

#### QoS Classes (8 Classes, 1 = Highest Priority)
```
Class 1 — Real-time (VoIP, video)
Class 2 — Interactive (RDP, Citrix)
Class 4 — Business apps (SAP, email)
Class 8 — Bulk/background (Windows Update, backups)
```

### Policy Based Forwarding (PBF)
Override the routing table for specific traffic:
```
Example: All YouTube traffic → exit via ISP-2 (secondary internet link)
Example: All SAP traffic     → exit via MPLS link
Example: VoIP traffic        → exit via dedicated voice circuit
```
PBF rules are evaluated **before** the routing table.

---

## 18. WildFire — Cloud-Based Malware Analysis

### What is WildFire?
- Cloud-based **sandboxing** service
- Unknown files are sent to Palo Alto's cloud, executed in a safe environment
- Verdict returned: Benign / Malware / Grayware / Phishing

### WildFire Workflow
```
1. File enters network
2. App-ID + Antivirus check → known malware? Block it.
3. Unknown file? → Submit to WildFire
4. WildFire executes file in sandbox (Windows, macOS, Android, Linux VMs)
5. Verdict generated within minutes
6. Signature created and distributed to ALL WildFire subscribers globally
7. Signature now protects all customers from this threat
```

### File Types Submitted
- PE executables (.exe, .dll, .sys)
- PDFs
- Office documents (.docx, .xlsx, .pptx with macros)
- APKs (Android)
- URLs (phishing page analysis)
- Flash, Java

### WildFire Subscriptions
- **Public cloud** — default, file shared with Palo Alto
- **Private cloud** — on-premises WF-500 appliance (for sensitive orgs)
- **Hybrid cloud** — mix of both

### WildFire Update Frequency
- New signatures distributed every **5 minutes** (WildFire subscription)
- Daily (without WildFire subscription)

---

## 19. Zone Protection & DoS Policies

### Zone Protection Profiles
Applied to a zone to protect against network-level attacks:

| Protection Type | Examples |
|---|---|
| Flood Protection | SYN flood, UDP flood, ICMP flood, ICMPv6 flood |
| Reconnaissance Protection | Port scans, host sweeps |
| Packet-Based Attacks | IP spoofing, fragmentation attacks, ICMP large packet |
| Protocol Protection | Block non-IPv4/IPv6, non-standard protocols |

### SYN Flood Protection — Three Modes

| Mode | How It Works |
|---|---|
| Red | Alert only |
| Yellow | SYN cookies enabled (firewall handles SYN before forwarding) |
| Red | Drop packets exceeding threshold |

### DoS Protection Policies
More granular than Zone Protection — can target specific source/destination pairs:
```
Classify:   Different per session (per source IP)
Aggregate:  Combined across all sessions matching the rule
```

---

## 20. Certificates & PKI on PAN-OS

### Why Certificates Matter in PAN-OS
- SSL Decryption requires a CA certificate
- GlobalProtect portal/gateway uses server certificates
- Admin authentication can use certificates
- IPsec VPN can use certificates instead of pre-shared keys

### Certificate Types in PAN-OS

| Type | Use |
|---|---|
| Self-signed CA | Create on-box, sign other certs locally |
| Enterprise CA | Use your internal PKI (AD CS) |
| Public CA | Use for GlobalProtect portal (DigiCert, Let's Encrypt) |
| Certificate Profile | Bundle of trusted CAs for authentication |

### Generating a Self-Signed CA
```
Device > Certificate Management > Certificates > Generate
  Common Name: PA-Root-CA
  Certificate Authority: ✅ checked
  Key Type: RSA 4096 or ECDSA 384
```

Then export and distribute to user devices via Group Policy.

### OCSP and CRL
- Firewall can check certificate revocation status
- OCSP (Online Certificate Status Protocol) — real-time check
- CRL (Certificate Revocation List) — download and cache

---

## 21. Troubleshooting & CLI Commands

### Most Used Operational CLI Commands

```bash
# Show interface status
show interface all
show interface ethernet1/1

# Show routing table
show routing route
show routing fib

# Show ARP table
show arp all

# Show sessions
show session all
show session id <session-id>

# Ping test
ping source <src-ip> host <dst-ip>

# Traceroute
traceroute source <src-ip> host <dst-ip>

# Show security policies
show running security-policy

# Test security policy (which rule matches?)
test security-policy-match from trust to untrust \
  source 10.10.10.5 destination 8.8.8.8 \
  application web-browsing protocol 6 destination-port 443

# Test NAT policy
test nat-policy-match from trust to untrust \
  source 10.10.10.5 destination 8.8.8.8 \
  protocol 6 destination-port 443

# Show system resources
show system resources
show system info

# Show HA status
show high-availability all
show high-availability state

# Show threat logs
show log threat
show log traffic

# DNS lookup from firewall
request dns-lookup fqdn google.com

# Software update
show system software status
request system software check
request system software download version 10.2.9
request system software install version 10.2.9
```

### Packet Capture (PCAP)
```bash
# Stage 1 — Set filter
debug dataplane packet-diag set filter match source 10.10.10.5 destination 8.8.8.8

# Stage 2 — Enable capture
debug dataplane packet-diag set capture stage firewall file /tmp/capture.pcap

# Stage 3 — Enable filter
debug dataplane packet-diag set capture on

# Stage 4 — Stop
debug dataplane packet-diag set capture off

# Download via WebGUI: Monitor > Packet Capture
```

### Common Troubleshooting Scenarios

| Problem | First Check |
|---|---|
| Traffic blocked | `test security-policy-match` → check rule order |
| NAT not working | `test nat-policy-match` → check NAT rule and security rule |
| VPN down | `show vpn tunnel` → check Phase 1 and Phase 2 status |
| App-ID wrong | Check if decryption is enabled, check app update version |
| High CPU | `show system resources` → check DP vs MP CPU separately |
| Commit fails | `show jobs all` → review commit job error detail |

---

## 22. Labs Summary — Quick Reference

### Lab 1: Basic Setup
- Access WebGUI at https://192.168.1.1
- Change admin password
- Set hostname, DNS, NTP
- Commit

### Lab 2: Interface & Zone Config
- Create Trust and Untrust zones
- Assign ethernet interfaces to zones
- Configure IP addresses on L3 interfaces
- Set default route via virtual router

### Lab 3: First Security Policy
- Allow Trust → Untrust for web-browsing, ssl
- Attach security profiles (AV, Anti-Spyware)
- Test with ping and browser

### Lab 4: Source NAT
- Create SNAT rule for Trust → Untrust
- Verify internet access from internal host

### Lab 5: Destination NAT (Port Forwarding)
- Expose internal web server to internet
- Create DNAT rule + security policy
- Test external access

### Lab 6: URL Filtering
- Enable URL filtering subscription
- Block social-networking category
- Alert on news category
- Test from internal host

### Lab 7: SSL Decryption
- Create forward proxy decryption policy
- Export and deploy CA cert
- Verify decryption with browser certificate viewer

### Lab 8: GlobalProtect VPN
- Configure portal and gateway on firewall
- Download and install GP client
- Test remote VPN connection

### Lab 9: Site-to-Site VPN
- Configure IKE gateway and IPsec tunnel
- Add static route and security policy
- Verify tunnel status and ping through it

### Lab 10: HA Setup
- Configure HA1 and HA2 links
- Set active/passive mode
- Test failover by disabling active firewall

---

## 23. Key Terms Glossary

| Term | Definition |
|---|---|
| NGFW | Next-Generation Firewall — identifies apps/users/content, not just ports |
| PAN-OS | Palo Alto Networks Operating System |
| App-ID | Engine that identifies applications using signatures |
| User-ID | Engine that maps IP addresses to usernames |
| Content-ID | Engine that inspects traffic payload for threats |
| SP3 | Single Pass Parallel Processing — all engines run simultaneously |
| Zone | Logical grouping of interfaces enforcing security policy |
| Commit | Command to activate staged configuration changes |
| Candidate Config | Staged but not yet active configuration |
| Running Config | Currently active configuration |
| IKE | Internet Key Exchange — VPN tunnel negotiation protocol |
| IPsec | IP Security — VPN encryption protocol |
| HIP | Host Information Profile — device compliance checking for GlobalProtect |
| WildFire | Palo Alto's cloud sandboxing service |
| PAN-DB | Palo Alto's URL categorization database |
| Panorama | Centralized management system for Palo Alto firewalls |
| ECMP | Equal Cost Multi-Path — load balancing across multiple routes |
| PBF | Policy Based Forwarding — route traffic based on policy, not routing table |
| DAG | Dynamic Address Group — IP groups populated by tags automatically |
| DIPP | Dynamic IP and Port — type of source NAT (standard "PAT") |
| PCAP | Packet Capture — recording of raw network traffic for analysis |
| vsys | Virtual System — multiple logical firewalls within one physical device |
| OSPF | Open Shortest Path First — link-state routing protocol |
| BGP | Border Gateway Protocol — internet routing protocol |
| SAML | Security Assertion Markup Language — SSO authentication standard |

---

## Quick Study Tips for Exams & Interviews

1. **Understand the 3 engines** (App-ID, User-ID, Content-ID) — almost every question links back to these.
2. **Know the commit model** — PAN-OS's candidate config approach is unique.
3. **Security policy = top-down, first match wins** — rule ordering is critical.
4. **NAT uses pre-NAT IPs** in security policy matching — common exam trap.
5. **application-default is always better than "any"** in the Service field.
6. **Decryption is required** for App-ID to see inside HTTPS — know this dependency.
7. **WildFire takes minutes, antivirus is instant** — different detection timelines.
8. **HA1 = control, HA2 = data** — know what happens if each link fails.
9. **Panorama pre-rules take priority** over device local rules.
10. **`test security-policy-match`** is your best friend for troubleshooting.

---

*Last updated: 2026 | Based on PAN-OS 11.x | Covers PCNSA & PCNSE objectives*
