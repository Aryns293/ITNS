### Summary of Information and Network Security (Unit 6)

This summary covers key topics related to IP Security (IPSec), Web Security (SSL/TLS), Time-Stamp Protocol (TSP), Secure Electronic Transaction (SET), Electronic Money, Wireless Access Protocol (WAP) Security, Firewalls, and Virtual Private Networks (VPNs), as presented in the provided content.

---

## 1. IP Security (IPSec)

**IPSec** is a suite of protocols designed by IETF to provide security at the **network layer** by authenticating and/or encrypting IP packets to ensure confidentiality, integrity, and authenticity.

### IPSec Modes

| Mode          | Description                                                                                      | Usage                         |
|---------------|--------------------------------------------------------------------------------------------------|-------------------------------|
| Transport     | Protects only the IP payload (data from transport layer). Adds IPSec header/trailer between transport and network layers. | Host-to-host communication     |
| Tunnel        | Protects entire IP packet, encapsulating it with a new IP header.                                | Gateway-to-gateway or host-to-gateway |

### IPSec Protocols

| Protocol                 | Function                                | Protocol Number | Key Characteristics                                                                                         |
|--------------------------|----------------------------------------|-----------------|-------------------------------------------------------------------------------------------------------------|
| Authentication Header (AH) | Provides source authentication and integrity | 51              | Uses hash function and symmetric keys; authenticates entire packet except mutable fields; no confidentiality. |
| Encapsulating Security Payload (ESP) | Provides confidentiality, authentication, and integrity | 50              | Encrypts payload and trailer; authentication data at packet end; more versatile than AH.                      |

### Security Services Provided by IPSec

| Service                | AH | ESP |
|------------------------|----|-----|
| Access Control         | Yes| Yes |
| Message Integrity      | Yes| Yes |
| Entity Authentication  | Yes| Yes |
| Confidentiality        | No | Yes |
| Replay Attack Protection | Yes| Yes |

- **Replay attacks** are mitigated using sequence numbers and sliding windows.
- **Security Association (SA):** A unidirectional logical connection between two entities, storing keys and algorithms.
- **Security Association Database (SAD):** Maintains inbound and outbound SAs; indexed by Security Parameter Index (SPI), destination address, and protocol.
- **Security Policy Database (SPD):** Defines policies for processing packets (drop, bypass, or apply IPSec).
- **Internet Key Exchange (IKE):** Protocol for establishing SAs using key exchange protocols like Oakley and SKEME, over ISAKMP carrier protocol.

### IKE Phases and Modes

| Phase        | Purpose                                        | Modes (Phase I)           | Notes                                     |
|--------------|------------------------------------------------|--------------------------|-------------------------------------------|
| Phase I      | Establishes secure channel and authenticates peers | Main mode, Aggressive mode | Main mode uses 6 messages; aggressive mode uses 3 messages |
| Phase II     | Negotiates IPSec SAs                             | Quick mode               | Uses keys from Phase I to create IPSec keys |

### Key Exchange and Cryptographic Concepts in IKE

- Diffie-Hellman (DH) key exchange is used with countermeasures against clogging (DoS) and replay attacks.
- Authentication can be based on pre-shared keys, public key encryption, or digital signatures.
- Perfect Forward Secrecy (PFS) is supported by exchanging new DH keys in Phase II.
- Key materials are derived from shared secrets using pseudorandom functions (PRF) and keyed hash functions (HMAC).

---

## 2. Web Security: SSL and TLS

### Web Security Considerations

- Web browsers and servers are easy to use but involve complex software with potential security flaws.
- Threats include **integrity attacks** (data modification), **confidentiality breaches** (eavesdropping), **denial of service** (DoS), and **authentication attacks** (impersonation).
- Attacks are categorized as **passive** (eavesdropping) or **active** (message modification, impersonation).
- Security is needed at different layers—network (IPSec), transport (SSL/TLS), and application.

### SSL (Secure Socket Layer)

- Developed by Netscape, SSL operates at the transport layer providing security services including fragmentation, optional compression, message integrity (MAC), and confidentiality (encryption).
- Uses **key exchange algorithms** such as RSA and Diffie-Hellman to create a **pre-master secret** which is used to derive the **master secret** and subsequent cryptographic keys.
- **Cipher suites** define the combination of key exchange, encryption, and hash algorithms.
- SSL sessions and connections allow session reuse and multiple connections per session.
- Four SSL protocols: Record, Handshake, ChangeCipherSpec, and Alert.
- The **Handshake protocol** has four phases: Establish security capabilities, Server authentication, Client authentication, and Finalization.
- **ChangeCipherSpec** signals readiness to use negotiated keys.
- **Alert Protocol** reports errors.
- SSL has been deprecated and replaced by TLS.

### TLS (Transport Layer Security)

- TLS evolved from SSL, standardized by IETF.
- Similar layered protocol structure with Handshake, ChangeCipherSpec, Alert, and an added Heartbeat protocol.
- Defines connection and session states, cryptographic parameters, and supports cipher suites.
- Uses HMAC with MD5 or SHA-1 for message integrity.
- TLS Handshake involves negotiation of cryptographic parameters, exchange of certificates, key exchange, and establishing encryption.
- Provides confidentiality and message integrity at the record protocol layer.
- Employs pseudorandom functions (PRF) to generate keys.
- **TLS 1.3** introduces significant improvements:
  - Removes obsolete algorithms and compressions.
  - Encrypted handshake messages after ServerHello.
  - Supports zero round-trip time (0-RTT) mode.
  - Uses HKDF for key derivation.
  - Adds elliptic curve cryptography and new signatures like EdDSA.
  - Removes ChangeCipherSpec except for compatibility.
  - Enforces forward secrecy by removing static RSA and Diffie-Hellman.

### Known Attacks on SSL/TLS

- Handshake protocol attacks exploiting implementation flaws.
- BEAST and CRIME attacks exploiting chosen-plaintext and compression vulnerabilities.
- PKI attacks due to weak certificate validation.
- Denial-of-Service attacks via handshake overload.

---

## 3. Time-Stamp Protocol (TSP)

- Defined in **RFC 3161**, TSP provides cryptographic proof that data existed at a specific time.
- A **Time-Stamping Authority (TSA)** signs a hash of the data with a timestamp, creating a **Time-Stamp Token (TST)**.
- The TST can be verified using the TSA’s public key.
- Applications include digital signature validation, legal evidence, financial transaction ordering, code signing, and chronological ordering of data.

---

## 4. Secure Electronic Transaction (SET) Protocol

- A PKI-based protocol designed to secure credit/debit card transactions online.
- Goals: **Authentication**, **Confidentiality**, **Integrity**, and **Interoperability**.
- Participants: Cardholder, Merchant, Issuer (cardholder’s bank), Acquirer (merchant’s bank), Payment Gateway, and Certification Authority.
- Features:
  - Mutual authentication using X.509 certificates.
  - Message confidentiality via encryption (traditionally DES).
  - Message integrity using RSA signatures and HMAC with SHA-1.
  - Dual signature concept to securely link Order Information (OI) and Payment Information (PI).
- Transaction Phases:
  - Customer places order.
  - Merchant authentication.
  - Customer sends OI and encrypted PI to merchant.
  - Merchant requests payment authorization from payment gateway.
  - Payment gateway verifies and authorizes payment.
  - Merchant confirms order and provides goods/services.
- Assumes valid bank accounts and trusted certificates.

---

## 5. Electronic Money

- Digital representation of currency used for transactions.
- Process:
  - Customer obtains electronic money from bank (encrypted data files representing money).
  - Customer uses electronic money to pay merchant.
  - Merchant redeems electronic money with their bank.
- Types of electronic money:

| Classification Basis               | Types                     | Description                                                                                           |
|----------------------------------|---------------------------|---------------------------------------------------------------------------------------------------|
| Traceability                     | Identified                | Unique serial number linked to customer; privacy concerns.                                        |
|                                  | Anonymous (Blinded money) | Customer blinds the serial number; bank signs without knowing the actual number; privacy preserved.|
| Bank Involvement in Transactions | Online                    | Bank verifies electronic money validity in real-time during transaction.                           |
|                                  | Offline                   | Bank verifies money authenticity offline; risk of double-spending exists especially if anonymous. |

- **Double-Spending Problem:** Risk of using the same electronic money multiple times; mitigated by bank verification but problematic for anonymous offline money.

---

## 6. Wireless Access Protocol (WAP) Security

### Key Security Risks in Wireless Networks

- Broadcast nature leads to susceptibility to eavesdropping and jamming.
- Mobility introduces risks due to device loss/theft and use of untrusted networks.
- Limited device resources constrain security implementations.
- Accessibility issues increase physical attack risks.
- Attack vectors include accidental/malicious association, ad hoc networks, identity theft (MAC spoofing), man-in-the-middle attacks, denial-of-service (DoS), and network injection.

### Wireless Security Measures

- Signal-hiding: Disable SSID broadcast, use cryptic SSIDs, reduce signal strength, place APs internally.
- Encryption of wireless traffic; use of authentication protocols.
- Site surveys and shielding to reduce interference and accidental DoS.
- IEEE 802.11X standard for port-based access control to prevent unauthorized access.
- Recommended practices:
  - Enable encryption.
  - Use antivirus, anti-spyware, and firewalls on endpoints.
  - Disable SSID broadcasting.
  - Change default router identifiers and admin passwords.
  - Restrict access to specific MAC addresses (recognizing MAC spoofing limitations).

### Mobility Security Threats (NIST SP 800-14)

- Physical theft or unauthorized access to mobile devices.
- Use of untrusted mobile devices and networks.
- Risks from applications by unknown parties and synchronization with uncontrolled devices.
- Exposure from location services (GPS).

### IEEE 802.11i Standard (Robust Security Network - RSN)

- Security phases: Discovery, Authentication, Key generation/distribution, Protected data transfer, Connection termination.
- Uses authentication servers and supports secure communication between wireless stations and access points.
- WPA and WPA2 (802.11i) address weaknesses in earlier WEP standard.

---

## 7. Firewalls

### Purpose

- Act as a **single choke point** to control traffic between trusted and untrusted networks.
- Provide perimeter defense and internal network segmentation (**defense in depth**).
- Facilitate monitoring, auditing, and enforcement of security policies.

### Design Goals

- All network traffic must flow through the firewall.
- Only authorized traffic allowed as per defined security policies.
- Firewall must be hardened against penetration.

### Capabilities

- Filter traffic based on IP address, protocol, port numbers.
- Protect against IP spoofing and routing attacks.
- Provide audit and logging capabilities.
- Serve as platform for NAT and VPNs.

### Limitations

- Cannot block attacks bypassing the firewall.
- Limited protection against internal threats and wireless attacks.
- Vulnerable to infected mobile devices introduced internally.

### Types of Firewalls

| Type                   | Description                                                                                      | Advantages                               | Disadvantages                           |
|------------------------|--------------------------------------------------------------------------------------------------|----------------------------------------|----------------------------------------|
| Packet Filtering       | Filters packets based on header info (IP addresses, ports, protocol).                            | Fast, transparent to users, simple     | Stateless, vulnerable to application-level attacks, spoofing, limited logging |
| Stateful Inspection    | Tracks TCP connection state and inspects packets accordingly.                                   | More secure than packet filters, track sessions, prevent spoofing | Limited to TCP, limited auditing       |
| Application Proxy (Gateway) | Acts as intermediary at application layer, relays traffic after authenticating and filtering.    | Enforces application protocols, user auth, auditing, filtering | Slower, requires client config, not scalable |
| Circuit-Level Proxy    | Relays TCP connections without inspecting contents; controls which connections are allowed.     | Less overhead than application proxies | Limited inspection, mostly for trusted internal users |

### DMZ (Demilitarized Zone) Networks

- Placed between external and internal firewalls.
- Hosts externally accessible systems like web servers.
- Protects internal network from attacks originating in DMZ and vice versa.
- Supports internal segmentation via additional firewalls.

---

## 8. Virtual Private Networks (VPN)

### Overview

- VPNs create **secure encrypted tunnels** over public networks like the internet.
- Provide **privacy**, **data integrity**, and **remote access** capabilities.

### Benefits

- Protect data from interception on public networks.
- Mask IP addresses to hide user identity and location.
- Enable secure access to corporate resources for remote users.
- Bypass geographic content restrictions.
- Prevent ISP throttling in some cases.

### Working

- Establish secure tunnel through handshake and key exchange.
- Encrypt data using negotiated keys.
- Redirect traffic through VPN server.
- Decrypt data at VPN endpoint before delivery.

### VPN Types and Protocols

| Type                  | Description                                         |
|-----------------------|-----------------------------------------------------|
| Remote Access VPN      | Connects individual hosts to a private network.     |
| Site-to-Site VPN       | Connects entire networks over public infrastructure.|
| Mobile VPN             | Supports seamless switching between networks (Wi-Fi, cellular).|
| MPLS VPN               | Uses MPLS backbone for scalable, efficient routing. |
| PPTP                   | Older, faster but insecure and mostly obsolete.      |
| IPsec VPN              | Secure tunneling with encryption; widely used.      |
| OpenVPN                | Open-source, flexible, supports auto-reconnect.     |

---

### Key Insights and Conclusions

- **IPSec** provides robust network-layer security but requires complex management of Security Associations and keys, typically handled by IKE.
- **SSL/TLS** protocols secure transport-layer communications; TLS 1.3 introduces significant security and performance enhancements.
- **Time-stamping** and **SET protocols** play critical roles in ensuring data integrity, transaction security, and non-repudiation in digital and financial transactions.
- **Electronic money** systems balance anonymity and traceability, with online/offline modes affecting double-spending risks.
- **Wireless security** requires layered defenses addressing inherent vulnerabilities due to broadcast media and mobility.
- **Firewalls** remain foundational for network perimeter security but must be complemented with internal controls and other security measures.
- **VPNs** are essential tools for secure remote connectivity and privacy, with multiple protocols suited for different use cases.

---

This summary encapsulates the technical principles, architectures, operational mechanisms, and security considerations of the covered network and web security technologies, strictly based on the provided source content.
