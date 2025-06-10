# Common Network Security Threats

## 1. Denial-of-Service (DoS) Attacks
A DoS attack floods a system with traffic to exhaust resources and make it unavailable to users. 

- **Impact**: Website or service downtime.
- **Real-World Example**: GitHub faced a 1.35 Tbps attack in 2018.
- **Mitigation**:
  - Use firewalls and load balancers.
  - Enable rate limiting.
  - Use anti-DDoS services (e.g., Cloudflare, AWS Shield).

## 2. Man-in-the-Middle (MITM) Attacks
In a MITM attack, the attacker secretly intercepts or alters communications between two parties.

- **Impact**: Data theft, especially credentials or personal info.
- **Real-World Example**: WiFi spoofing attacks in public places.
- **Mitigation**:
  - Use HTTPS and strong encryption (TLS).
  - Avoid public WiFi or use VPNs.

## 3. Spoofing Attacks
Spoofing involves pretending to be another system or person to gain unauthorized access.

- **Impact**: System compromise, data theft.
- **Types**: IP spoofing, email spoofing, ARP spoofing.
- **Mitigation**:
  - Use authentication and validation checks.
  - Enable SPF/DKIM/DMARC for email.

