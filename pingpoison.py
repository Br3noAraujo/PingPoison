#!/usr/bin/python3
#! coding: utf-8
"""Coded By Br3noAraujo"""

import sys
import os
import logging
import argparse
from argparse import RawTextHelpFormatter
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style, init as colorama_init
from scapy.all import sniff, send, IP, ICMP, Raw, conf
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Banner
BANNER = f'''
{Fore.GREEN}
  .-.    __
 |   |  /\ \\
 |   |  \_\/      __        {Fore.RED}.-.{Fore.GREEN}
 |___|        __ /\\ \      {Fore.RED}/:::\\{Fore.GREEN}
 {Fore.RED}|:::|{Fore.GREEN}          \\\\_\\/     {Fore.RED}/::::/{Fore.GREEN}
 {Fore.RED}|:::|{Fore.GREEN}                   {Fore.RED}/::::/{Fore.GREEN}
 {Fore.RED}':::'{Fore.GREEN}__   _____ {Fore.RED}_____{Fore.GREEN}  /    /
     / /\ /     {Fore.RED}|:::::\{Fore.GREEN} \   /{Fore.RED}POISON{Fore.GREEN}
     \/_/ \     {Fore.RED}|:::::/{Fore.GREEN}  `"{Fore.RED}PING{Fore.GREEN}
        __ `-----{Fore.RED}----`{Fore.GREEN}
       /\ \\
       \_\/
{Style.RESET_ALL}{Fore.LIGHTGREEN_EX}        Stealth Defensive ICMP Poisoner
    By Br3noAraujo | github.com/Br3noAraujo
{Style.RESET_ALL}'''

# Logger setup
def setup_logger(log_path, debug=False):
    logger = logging.getLogger("pingpoison")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s | %(message)s')
    fh.setFormatter(formatter)
    if not logger.hasHandlers():
        logger.addHandler(fh)
    return logger

# Root/admin check
def check_root():
    if os.name == 'nt':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
    else:
        is_admin = (os.geteuid() == 0)
    if not is_admin:
        print(f"{Fore.LIGHTRED_EX}[!] This script must be run as root/Administrator!{Style.RESET_ALL}")
        sys.exit(1)

# GeoIP lookup using local database
def geoip_lookup(reader, ip):
    if not GEOIP_AVAILABLE or not reader:
        return None
    try:
        response = reader.country(ip)
        return response.country.iso_code
    except Exception:
        return None

# ICMP forger logic: crafts and sends forged ICMP replies
def forge_and_reply(pkt, debug, logger, geoip_reader=None):
    if not pkt.haslayer(ICMP) or pkt[ICMP].type != 8:
        return
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    ttl = pkt[IP].ttl
    size = len(pkt)
    country = geoip_lookup(geoip_reader, src_ip) if geoip_reader else None

    # Forge reply: high latency, weird TTL, fragmentation
    forged_ttl = 13  # Unusual TTL
    forged_id = os.getpid() & 0xFFFF
    forged_seq = (pkt[ICMP].seq + 42) & 0xFFFF
    forged_payload = b"\x00" * (size + 32)  # Larger payload
    forged_reply = IP(src=dst_ip, dst=src_ip, ttl=forged_ttl, flags="MF")/ICMP(type=0, id=forged_id, seq=forged_seq)/Raw(load=forged_payload)
    send(forged_reply, verbose=0)

    log_msg = f"SRC={src_ip} TTL={ttl} SIZE={size}"
    if country:
        log_msg += f" COUNTRY={country}"
    logger.info(log_msg)
    if debug:
        print(f"{Fore.LIGHTGREEN_EX}[ICMP] {log_msg}{Style.RESET_ALL}")

# Block real ICMP replies using nftables or iptables
def block_real_icmp():
    if os.name == 'nt':
        print(f"{Fore.LIGHTRED_EX}[!] ICMP blocking not supported on Windows.{Style.RESET_ALL}")
        return
    import subprocess
    def run_cmd(cmd):
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError as e:
            return False
    # Try nftables first
    nft_table = ["nft", "add", "table", "inet", "filter"]
    nft_chain = ["nft", "add", "chain", "inet", "filter", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"]
    nft_rule = ["nft", "add", "rule", "inet", "filter", "input", "icmp", "type", "echo-request", "drop"]
    run_cmd(nft_table)
    run_cmd(nft_chain)
    if run_cmd(nft_rule):
        print(f"{Fore.LIGHTGREEN_EX}[+] Blocked real ICMP echo replies using nftables.{Style.RESET_ALL}")
        return
    # If nftables fails, try iptables
    ipt_rule = ["iptables", "-C", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"]
    ipt_add = ["iptables", "-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"]
    if not run_cmd(ipt_rule):
        if run_cmd(ipt_add):
            print(f"{Fore.LIGHTGREEN_EX}[+] Blocked real ICMP echo replies using iptables.{Style.RESET_ALL}")
            return
    else:
        print(f"{Fore.LIGHTGREEN_EX}[+] ICMP echo-request DROP rule already present in iptables.{Style.RESET_ALL}")
        return
    print(f"{Fore.LIGHTRED_EX}[!] Failed to block real ICMP replies. Check permissions or configure manually.{Style.RESET_ALL}")

# Main function: argument parsing and main logic
def main():
    colorama_init(autoreset=True)
    print(BANNER)
    # Short usage if no arguments
    if len(sys.argv) == 1:
        print(f"{Fore.LIGHTGREEN_EX}Usage:{Style.RESET_ALL} sudo python3 pingpoison.py [--iface eth0]\n \t[--deny-real-ping] [--debug] [--geoip-db <db>] [--log]\n" \
              f"Try 'python3 pingpoison.py --help' for full details.")
        sys.exit(0)
    check_root()

    home = Path.home()
    log_dir = home / ".pingpoison" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "pingpoison.log"

    parser = argparse.ArgumentParser(
        description="""
Stealth ICMP Poisoner - Coded By Br3noAraujo (github.com/Br3noAraujo)

PingPoison is a defensive tool to confuse network scanners and log ping attempts.

Usage examples:
  sudo python3 pingpoison.py --iface eth0 --deny-real-ping --debug
  sudo python3 pingpoison.py --iface wlan0 --geoip-db /path/GeoLite2-Country.mmdb

Arguments:
  --iface         Network interface to sniff on (e.g., eth0, wlan0)
  --deny-real-ping  Block real ICMP echo replies from the OS (iptables/nftables)
  --debug         Show received ICMP packets live
  --geoip-db      Path to local GeoIP2 database (optional)
  --log           Enable logging (default: always on)

Logs are saved to ~/.pingpoison/logs/pingpoison.log
Requires root/admin. Colorful output, poison/venom theme.
""",
        formatter_class=RawTextHelpFormatter)
    parser.add_argument("--deny-real-ping", "-d", action="store_true", help="Block real ICMP echo replies (root required)")
    parser.add_argument("--log", "-l", action="store_true", help="Enable logging to file (default: always on)")
    parser.add_argument("--debug", action="store_true", help="Print received ping data live")
    parser.add_argument("--geoip-db", type=str, default=None, help="Path to local GeoIP2 database (mmdb)")
    parser.add_argument("--iface", type=str, default=None, help="Network interface to sniff on (e.g., eth0, wlan0)")
    args = parser.parse_args()

    logger = setup_logger(log_path, debug=args.debug)
    geoip_reader = None
    if args.geoip_db:
        if GEOIP_AVAILABLE:
            try:
                geoip_reader = geoip2.database.Reader(args.geoip_db)
            except Exception:
                print(f"{Fore.LIGHTRED_EX}[!] Failed to load GeoIP2 database.{Style.RESET_ALL}")
        else:
            print(f"{Fore.LIGHTRED_EX}[!] geoip2 not installed. Skipping geolocation.{Style.RESET_ALL}")

    if args.deny_real_ping:
        block_real_icmp()

    print(f"{Fore.LIGHTGREEN_EX}[+] Listening for ICMP Echo Requests...{Style.RESET_ALL}")
    sniff_kwargs = {
        "filter": "icmp and icmp[icmptype]=8",
        "prn": lambda pkt: forge_and_reply(pkt, args.debug, logger, geoip_reader),
        "store": 0
    }
    if args.iface:
        sniff_kwargs["iface"] = args.iface

    # Debug mode: show all ICMP packets received
    if args.debug:
        print(f"{Fore.LIGHTGREEN_EX}[DEBUG] Debug mode: showing all ICMP packets received...{Style.RESET_ALL}")
        def debug_sniff(pkt):
            print(f"{Fore.LIGHTGREEN_EX}[DEBUG] ICMP packet: {pkt.summary()}{Style.RESET_ALL}")
            forge_and_reply(pkt, args.debug, logger, geoip_reader)
        sniff_kwargs["prn"] = debug_sniff

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print(f"{Fore.LIGHTGREEN_EX}\n[!] Exiting PingPoison...{Style.RESET_ALL}")
    finally:
        if geoip_reader:
            geoip_reader.close()

if __name__ == "__main__":
    main()
