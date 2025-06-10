# Common Network Security Threats

## Introduction
Modern networks are constantly targeted by attackers exploiting a wide range of vulnerabilities. Understanding these threats is essential to developing defensive strategies. This report covers three major network security threats: **Denial-of-Service (DoS) attacks**, **Man-in-the-Middle (MITM) attacks**, and **Spoofing**. For each, we explain how the attack works, its real-world impact, and mitigation strategies.

---

## 1. Denial-of-Service (DoS) Attacks

### What It Is:
A Denial-of-Service attack overwhelms a system with excessive requests, making services unavailable to legitimate users.

### Types:
- **DoS** – Single system attacks the target.
- **DDoS (Distributed DoS)** – Multiple systems attack simultaneously, often using botnets.

### Example:
- **GitHub (2018)** was hit by a 1.35 Tbps DDoS attack using **Memcached servers**.
- Result: GitHub experienced temporary downtime and had to reroute traffic through a DDoS mitigation service.

### Impact:
- Business disruption
- Revenue loss
- Reputation damage

### Mitigation:
- Deploy Web Application Firewalls (WAFs)
- Use DDoS mitigation services (Cloudflare, Akamai)
- Implement rate limiting and traffic filtering

---

## 2. Man-in-the-Middle (MITM) Attacks

### What It Is:
A MITM attack occurs when an attacker intercepts communications between two parties without their knowledge.

### Techniques:
- **ARP spoofing**
- **Session hijacking**
- **SSL stripping**

### Example:
- In public Wi-Fi hotspots, attackers set up fake access points to intercept credentials and data.

### Impact:
- Credential theft
- Unauthorized access to accounts
- Compromised data integrity

### Mitigation:
- Always use HTTPS (with valid certificates)
- Use VPNs on public networks
- Enable certificate pinning
- Deploy mutual TLS for high-security environments

---

## 3. Spoofing Attacks

### What It Is:
Spoofing is impersonation — an attacker fakes their identity to trick the victim or the system.

### Types:
- **IP Spoofing**: Falsifying the source IP address
- **Email Spoofing**: Faking a legitimate sender’s address
- **ARP Spoofing**: Mapping the attacker’s MAC address to a legitimate IP

### Example:
- **Email Spoofing** is widely used in phishing attacks. A fake email appearing to come from a trusted source prompts the user to click malicious links.

### Impact:
- System access by unauthorized users
- Successful phishing or social engineering
- Network redirection and data loss

### Mitigation:
- Use DNS and IP address filtering
- Enable email verification protocols (SPF, DKIM, DMARC)
- Monitor ARP tables and apply dynamic ARP inspection (DAI)

---

## Conclusion

Understanding and mitigating network threats like DoS, MITM, and Spoofing are foundational to good cybersecurity hygiene. These attacks continue to evolve, and proactive defense mechanisms — including updated systems, employee training, encryption, and firewalls — are essential to protect both users and infrastructure.

---

## References
- OWASP. "Man-in-the-Middle Attack." [owasp.org](https://owasp.org)
- Cloudflare. "What is a DDoS attack?"
- MITRE ATT&CK Framework
- KrebsOnSecurity blog
