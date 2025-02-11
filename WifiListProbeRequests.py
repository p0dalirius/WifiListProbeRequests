#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : WifiListProbeRequests.py
# Author             : Podalirius (@podalirius_)
# Date created       : 1 Apr 2022


import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11Elt, Dot11


def parseArgs():
    print("WifiListProbeRequests v1.1 - by Remi GASCOU (Podalirius)\n")

    parser = argparse.ArgumentParser(description="Monitor 802.11 probe requests from a capture file or network sniffing!")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose mode")
    parser.add_argument("-d", "--device", dest="device", default='', help="Device address filter.")
    parser.add_argument("-l", "--logfile", dest="logfile", default=None, help="Log output to file.")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--pcap", dest="pcap", default=None, help="Capture file to read packets from.")
    group.add_argument("-i", "--interface", dest="interface", default=None, help="Interface to listen on.")
    return parser.parse_args()


def packet_filter(pkt, device, logfile):
    if Dot11ProbeReq in pkt and Dot11Elt in pkt[Dot11ProbeReq]:
        device_addr = pkt.addr2
        if Dot11 in pkt and device_addr.startswith(device):
            if Dot11ProbeReq in pkt:
                pkt = pkt[Dot11ProbeReq][Dot11Elt]
                # SSID
                if pkt.ID == 0:
                    if len(pkt.info) != 0:
                        try:
                            requested_ssid = pkt.info.decode('utf-8')
                            message = "[>] Device '%s' is searching for '%s'" % (device_addr, requested_ssid)
                        except UnicodeError as e:
                            message = "[>] Device '%s' is searching for %s (Could not properly decode SSID)" % (device_addr, str(pkt.info))

                        print(message)
                        if logfile is not None:
                            f = open(logfile, "a")
                            f.write(message + "\n")
                            f.close()


if __name__ == '__main__':
    options = parseArgs()

    if options.logfile is not None:
        open(options.logfile, 'w').close()

    if options.pcap is not None:
        print('[>] Reading packets from "%s" capture file ...' % os.path.basename(options.pcap))
        packets = rdpcap(options.pcap)
        print('[>] Read %d packets.' % len(packets))
        for pkt in packets:
            packet_filter(pkt, options.device, options.logfile)

    elif options.interface is not None:
        if len(os.popen('which airmon-ng').read().strip()) != 0:
            if os.geteuid() == 0:
                print('[>] Switching "%s" to monitor mode ...' % options.interface)
                if options.verbose:
                    print('[debug] airmon-ng start "%s"' % options.interface)
                    os.system('airmon-ng start "%s"' % options.interface)
                else:
                    os.popen('airmon-ng start "%s"' % options.interface).read()

                try:
                    sniff(iface="%smon" % options.interface, prn=lambda pkt:packet_filter(pkt, options.device, options.logfile))
                except KeyboardInterrupt as e:
                    print("\r[>] Stopping packet catpure ...")

                print('[>] Rolling back "%s" to normal mode ...' % options.interface)
                if options.verbose:
                    print('[debug] airmon-ng stop "%smon"' % options.interface)
                    os.system('airmon-ng stop "%smon"' % options.interface)
                else:
                    os.popen('airmon-ng stop "%smon"' % options.interface).read()
            else:
                print("[!] You need to be root to use monitor mode.")
        else:
            print("[!] airmon-ng is not installed. Install it with 'apt install aircrack'.")
