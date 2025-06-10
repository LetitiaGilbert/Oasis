# Basic Network Scanning with Nmap

## Objective
To perform multiple types of scans using **Nmap** on a localhost target (`127.0.0.1`) to identify open ports, services, and analyze network exposure.

---

## Tools & Environment
- **Nmap v7.94**
- **Kali Linux / Parrot OS**
- Target: `127.0.0.1` (localhost)

---

## Commands Executed

| Command                         | Purpose                             |
|---------------------------------|-------------------------------------|
| `nmap 127.0.0.1`                | Basic TCP scan                      |
| `nmap -v 127.0.0.1`             | Verbose scan                        |
| `nmap -sV 127.0.0.1`            | Service & version detection         |
| `nmap -sU 127.0.0.1`            | UDP port scan                       |
| `nmap -sV --allports 127.0.0.1` | Scan all 65535 ports with versions  |
| `nmap -sA / -sW / -sM`          | ACK, Window, Maimon scans for stealth analysis |

---

## Key Findings

### TCP Ports
- **5000/tcp**: RTSP service (AirTunes)
- **6789/tcp**: IBM DB2 Admin (ssl/possibly secure)
- **7000/tcp**: RTSP service (AirTunes)

### UDP Ports
- **5353/udp**: mDNS/Zeroconf
- **137,138/udp**: NetBIOS-related (open|filtered)

### Unusual/Filtered Results
- ACK, Window, Maimon scans returned no useful data (likely due to localhost firewall rules).

---

## Interpretation
- **RTSP** services often relate to media streaming. Should be restricted or monitored.
- **DB2 admin port** (6789) should not be open unless required and secured with strong authentication.
- **mDNS** and **NetBIOS** on UDP may allow local network discovery, which could be risky.

---

## Screenshots

All screenshots of the scans are in the `screenshots/` folder:

| Scan Type         | File                        |
|------------------|-----------------------------|
| Basic Scan        | `scan1.png`                |
| Verbose           | `scan2.png`                |
| Version Detection | `scan3.png`                |
| All Ports         | `scan4.png`                |
| UDP               | `scan5.png`                |
| ACK               | `scan6.png`                |
| Window            | `scan7.png`                |
| Maimon            | `scan8.png`                |

---

## Conclusion

This task demonstrates the use of various Nmap scan types to probe and analyze the open ports and services of a local host. Understanding the tools and methods attackers might use allows defenders to better secure their networks.

---

## References
- [Nmap Official Guide](https://nmap.org/book/)
- [Nmap Cheat Sheet](https://github.com/cheatsheetseries/cheatsheets/Nmap_Cheat_Sheet.md)
- [Explaining Nmap Scan Types](https://nmap.org/docs.html)
