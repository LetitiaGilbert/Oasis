# Social Engineering Attacks

## Introduction
Social engineering is a psychological attack technique where attackers manipulate individuals into revealing confidential information or performing actions that compromise security. These attacks exploit **human error**, rather than system vulnerabilities. This report focuses on the most common types — **phishing**, **pretexting**, and **baiting** — with real-world examples and strategies for prevention.

---

## 1. Phishing

### What It Is:
Phishing involves fraudulent communication (usually emails or messages) that appears to come from a trusted source to trick users into revealing sensitive data like passwords or credit card numbers.

### Techniques:
- Fake login pages
- Urgent message prompts ("Your account is suspended!")
- Attachments with malware

### Real-World Example:
- **Google & Facebook Phishing Scam (2013–2015)**: A Lithuanian hacker impersonated a Taiwanese hardware vendor and tricked employees into wiring over $100 million.

### Impact:
- Credential theft
- Malware infection
- Financial fraud

### Mitigation:
- Enable spam filters and 2FA
- Train employees to identify fake emails
- Hover over links before clicking
- Use email authentication protocols (SPF, DKIM, DMARC)

---

## 2. Pretexting

### What It Is:
Pretexting involves the attacker creating a false identity or scenario to gain access to information or systems. It often includes impersonating a trusted figure (like IT staff or HR).

### Techniques:
- Fake support calls
- Pretending to be an executive requesting urgent action
- Impersonation of law enforcement

### Real-World Example:
- In 2006, a reporter used pretexting to obtain the private phone records of HP board members, claiming to be from the phone company.

### Impact:
- Unauthorized access
- Data leakage
- Breach of trust within organizations

### Mitigation:
- Always verify identities (e.g., call back on official numbers)
- Use strict internal processes for handling sensitive info
- Limit access to privileged data

---

## 3. Baiting

### What It Is:
Baiting uses false promises to lure users into compromising their systems. The "bait" can be physical (e.g., USB drives) or digital (e.g., free software).

### Techniques:
- Infected USBs labeled "Confidential" left in public areas
- Free movie/music downloads infected with malware

### Real-World Example:
- An experiment by the University of Illinois found that **48%** of people who found a USB in a parking lot plugged it into their PC without questioning its origin.

### Impact:
- Malware or ransomware infections
- Access to internal systems
- Potential data exfiltration

### Mitigation:
- Educate users on the risks of unknown devices
- Block unauthorized USB access
- Use endpoint protection software

---

## Prevention Strategies

### Technical Measures:
- Multi-Factor Authentication (MFA)
- Email security gateways and antivirus tools
- Network monitoring and anomaly detection

### Organizational Measures:
- Regular employee awareness training
- Simulated phishing tests
- Clear incident reporting procedures

---

## Conclusion
Social engineering is one of the most effective tools in an attacker’s arsenal because it targets the human element. Despite sophisticated security technologies, a single moment of human error can compromise an entire system. Therefore, **awareness, training, and layered defenses** are essential to reduce risk and build a strong cybersecurity culture.

---

## References
- Verizon Data Breach Investigations Report (DBIR)
- CISA Phishing Guidance
- NIST Special Publication 800-50: Building an IT Security Awareness Program
- KrebsOnSecurity: "Social Engineering Redefined"

