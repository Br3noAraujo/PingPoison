# 🐍☠️ PingPoison ☠️🦠

<p align="center">
  <img src="https://i.imgur.com/gBmU7N8.png" alt="PingPoison Showcase" width="600"/>
</p>

---

## {🧪} About

**PingPoison** is a stealthy, cross-platform defensive tool that listens for incoming ICMP Echo Requests (ping) and replies with forged, confusing packets to poison network scanners and fingerprinting tools. It logs every ping attempt with timestamp, source IP, and (optionally) geolocation. Inspired by hacker culture, Unix aesthetics, and raw practicality.

---

## {🕸️} Features
- 🐍 **Poisonous forged ICMP replies** (weird TTL, fragmentation, oversized payload)
- 🦠 **Blocks real system ping replies** (optional, via iptables/nftables)
- 🧬 **Logs every ping attempt** (timestamp, IP, TTL, size, country)
- 🧪 **GeoIP support** (optional, local database)
- 🖤 **Colorful, hacker-themed CLI output**
- 🏴 **No OOP, no web dependencies, no GUI**
- 🐧 **Works on Linux, macOS, Windows**

---

## {⚡} Quick Start

```bash
pip install -r requirements.txt
sudo python3 pingpoison.py --iface eth0 --deny-real-ping --debug
```

---

## {💀} Usage Example

<p align="center">
  <img src="https://i.imgur.com/l2qq57B.png" alt="PingPoison Defense Command" width="600"/>
</p>

- **Recommended defense command:**

```bash
sudo python3 pingpoison.py --iface eth0 --deny-real-ping --debug
```

- Replace `eth0` with your network interface (use `ip a` to list).

---

## {🐍} Live Demo

<p align="center">
  <img src="https://i.imgur.com/AYaloDq.png" alt="PingPoison Live Demo" width="600"/>
</p>

---

## {📜} Logging
- All ping attempts are logged to: `~/.pingpoison/logs/pingpoison.log`
- Log format: `timestamp | SRC=<ip> TTL=<ttl> SIZE=<size> COUNTRY=<country>`

---

## {🧰} Requirements
- Python 3.7+
- [Scapy](https://scapy.net/)
- [colorama](https://pypi.org/project/colorama/)
- [geoip2](https://pypi.org/project/geoip2/) (optional, for GeoIP)
- Root/Administrator privileges for packet sniffing and firewall rules

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## {👤} Author
- Coded by [Br3noAraujo](https://github.com/Br3noAraujo)

---

## {⚖️} License
MIT License. Free for hackers, sysadmins, and defenders everywhere. 