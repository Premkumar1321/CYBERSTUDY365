#!/usr/bin/env python3

"""
Cyber Project for study purpose.

"""

import os
import sys
import random
import signal
import time

# Configuration
LOG_ENABLED = False
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", f"Honeybox_log_{os.getenv('USER', 'default')}.log")
PROTECTED_MODE = True
COLOR_OUTPUT = True
VERSION = "1.8"

def write_log(message, module="Core"):
    if LOG_ENABLED:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        log_message = f"[{timestamp} - {module}] {message}\n"
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(log_message)

def signal_handler(sig, frame):
    print("\n[*] Exiting Honeybox...")
    write_log("exiting", "Core")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def display_banner():
    banners = [
        """
       ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
   ┃        CYBERSTUDY365                ┃
   ┃    Your Digital Learning Platform   ┃
   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

"""
    ]
    print(random.choice(banners))

def get_input(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return ""

def base64_tools():
    print("[*] Base64 Encoder & Decoder module placeholder.")
    # Implement base64 encode/decode functionality here

def multi_digest_tools():
    print("[*] Multi-Digest (MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD-160) module placeholder.")
    # Implement digest hashing functionality here

def hash_password_cracker():
    print("[*] Hash Password Cracker module placeholder.")
    # Implement hash cracking functionality here

def secure_password_generator():
    print("[*] Secure Password Generator module placeholder.")
    # Implement secure password generation here

def net_dos_tester():
    if PROTECTED_MODE and os.geteuid() != 0:
        print("Sorry, you need root privileges to run this module.")
        return
    print("[*] Net DoS Tester module placeholder.")
    # Implement DoS testing functionality here

def tcp_port_scanner():
    print("[*] TCP Port Scanner module placeholder.")
    # Implement port scanning functionality here

def honeypot_module():
    print("[*] Honeypot module placeholder.")
    # Implement honeypot functionality here

def fuzzer_module():
    print("[*] Fuzzer module placeholder.")
    # Implement fuzzer functionality here

def dns_and_host_gathering():
    print("[*] DNS and Host Gathering module placeholder.")
    # Implement DNS and host gathering functionality here

def mac_address_geolocation():
    print("[*] MAC Address Geolocation module placeholder.")
    # Implement MAC address geolocation functionality here

def http_directory_bruteforce():
    print("[*] HTTP Directory Bruteforce module placeholder.")
    # Implement HTTP directory bruteforce functionality here

def http_common_files_bruteforce():
    print("[*] HTTP Common Files Bruteforce module placeholder.")
    # Implement HTTP common files bruteforce functionality here

def license_and_contact():
    print("""
    X------------------------------------X
    | Copyright (C) 2012, 2013, 2014     |
    |                                    |
    |   Minzsec                          |
    |   www.facebook.com/rootnameshadow  |
    X------------------------------------X

    CYBERSTUDY365 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CYBERSTUDY365 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Honeybox. Or you need some configuration If not, see <http://www.gnu.org/licenses/>.
    """)

def main_menu():
    write_log("CYBERSTUDY365 loaded", "Core")
    display_banner()
    print(f" CYBERSTUDY365 {VERSION} \n")

    while True:
        print("--------- Menu")
        print("1- Cryptography tools")
        print("2- Network tools")
        print("3- Web")
        print("4- IP grabber")
        print("5- Geolocation IP")
        print("6- Mass attack")
        print("7- License and contact")
        print("8- Exit\n")

        choice = get_input("   -> ")

        if choice == "1":
            print("\n1- Base64 Encoder & Decoder")
            print("2- Multi-Digest (MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD-160)")
            print("3- Hash Password Cracker (MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD-160)")
            print("4- Secure Password Generator")
            print("\n0- Back\n")
            sub_choice = get_input("   -> ")
            if sub_choice == "0":
                continue
            elif sub_choice == "1":
                base64_tools()
            elif sub_choice == "2":
                multi_digest_tools()
            elif sub_choice == "3":
                hash_password_cracker()
            elif sub_choice == "4":
                secure_password_generator()
            else:
                print("\nInvalid option.\n")

        elif choice == "2":
            print("\n1- Net DoS Tester")
            print("2- TCP port scanner")
            print("3- Honeypot")
            print("4- Fuzzer")
            print("5- DNS and host gathering")
            print("6- MAC address geolocation (samy.pl)")
            print("\n0- Back\n")
            sub_choice = get_input("   -> ")
            if sub_choice == "0":
                continue
            elif sub_choice == "1":
                net_dos_tester()
            elif sub_choice == "2":
                tcp_port_scanner()
            elif sub_choice == "3":
                honeypot_module()
            elif sub_choice == "4":
                fuzzer_module()
            elif sub_choice == "5":
                dns_and_host_gathering()
            elif sub_choice == "6":
                mac_address_geolocation()
            else:
                print("\nInvalid option.\n")

        elif choice == "3":
            print("\n1- HTTP directory bruteforce")
            print("2- HTTP common files bruteforce")
            print("\n0- Back\n")
            sub_choice = get_input("   -> ")
            if sub_choice == "0":
                continue
            elif sub_choice == "1":
                http_directory_bruteforce()
            elif sub_choice == "2":
                http_common_files_bruteforce()
            else:
                print("\nInvalid option.\n")

        elif choice == "4":
            print("\nIP grabber module is not implemented yet.\n")

        elif choice == "5":
            print("\nGeolocation IP module is not implemented yet.\n")

        elif choice == "6":
            print("\nMass attack module is not implemented yet.\n")

        elif choice == "7":
            license_and_contact()

        elif choice == "8":
            print("\nExiting Honeybox. Goodbye!\n")
            write_log("exiting", "Core")
            break

        else:
            print("\nInvalid option.\n")

        print("\n[*] Module execution finished.\n")

if __name__ == "__main__":
    main_menu()
