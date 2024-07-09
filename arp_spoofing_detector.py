#!/usr/bin/python3
import os
import re
import psutil
import argparse
from socket import gethostname, gethostbyname
from itertools import combinations
from colorama import Fore
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr1, sniff
from scapy.config import conf


class ArpSpoofDetector:
    def __init__(self, interface):
        self.net = {'announce_mac': '00:00:00:00:00:00', 'broadcast_mac': 'ff:ff:ff:ff:ff:ff', 'timeout': 2}
        self.arp_table = {}
        self.responded_hosts: dict = {}
        self.packet_timestamp: dict = {}
        self.interface = interface
        self.interface_mac = self._get_interface_attributes()
        self.host_ip = gethostbyname(gethostname())
        self._load_arp_table()
        conf.iface = interface
        conf.verb = 0
        print(Fore.YELLOW + 'ARP Spoof Detector has been initialized, listening for ARP packets. Press Ctrl C To stop...')

    def is_at_request(self, arp_packet):
        """
            * Summary: Sniff only ARP Packets that their OP-Code "is-at" or ARP announcement
            * Params:  ARP packet to check
            * Returns: True if it's an ARP announcment packet
        """
        return arp_packet.getlayer(ARP).hwdst == self.net.get('announce_mac') and arp_packet.getlayer(ARP).pdst == arp_packet.getlayer(ARP).psrc \
            or arp_packet.getlayer(ARP).op == 2

    def _get_interface_attributes(self):
        """
            * Params: interface as a string
            * Return: interface MAC address as string, IP of default gateway as string
        """
        net_cards = [(iface, iface_attrib) for iface, iface_attrib in psutil.net_if_addrs().items()]
        for iface, iface_attrib in net_cards:
            if iface == self.interface:
                mac_address = [attrib.address for attrib in iface_attrib if attrib.family == psutil.AF_LINK][0]

                return mac_address.replace('-', ':').lower()

    def _load_arp_table(self) -> None:
        """
            * Summary: add all IP, MAC pairs stored in the machine into ARP_TABLE using the command and pattern in
            *          different platform (Linux, Windows) then check if there are IPs associated with the same MAC
            *          address which means that the machine is already under ARP spoofing attack.
            * Return:  None
        """
        if psutil.LINUX:
            # Linux Operating System
            # Find all strings containing: <(IP) MAC> (example (192.168.33.1) at 54:db:a2:20:3a:80) in command arp -an
            pattern = (r'\(([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\) at ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})')
            output = os.popen('arp -an').read()

        else:
            # Windows Operating System
            # Find all strings containing: <IP     MAC> (example 192.168.33.1     54-db-a2-20-3a-80) in command arp -a
            pattern = (r'([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\s+ ([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})')
            output = os.popen('arp -a').read()

        parsed_output: list[tuple] = re.findall(pattern, output)
        temp_arp_table = {}

        for ip, mac in parsed_output:
            temp_arp_table[ip] = mac.replace('-', ':')

        temp_arp_table[self.host_ip] = self.interface_mac

        for ip, mac in temp_arp_table.items():
            flag = False
            for ip2, mac2 in temp_arp_table.items():
                if ip != ip2 and mac == mac2 and mac != self.net.get('broadcast_mac'):
                    print(Fore.RED + f"[!] {ip} and {ip2} associated with same MAC: {mac}. ARP Spoofing Detected!" + Fore.RESET)
                    flag = True

            if not flag and mac != self.net.get('broadcast_mac'):
                self.arp_table[ip] = mac

    def _duplicate_mac(self, arp_packet) -> int:
        """
            * Summary: Add the Sender / Target IP with MAC address to the ARP table if it's a new IP. But if the IP
            *          already exist in the ARP table and the MAC in the packet it's different from the MAC in the ARP
            *          table, add it to list of suspected MACs (There is an attempt of ARP Spoofing with this IP address).
            * Params:  ARP Packet
            * return:  0. The ARP is-at packet is from a valid host.
            *          1. if the sender IP use same the MAC as another IP address.
            *          2. if the target IP use same the MAC as another IP address.
        """
        reversed_arp_table = {mac: ip for ip, mac in self.arp_table.items()}
        sender_mac = arp_packet.getlayer(ARP).hwsrc
        target_mac = arp_packet.getlayer(ARP).hwdst
        sender_ip = arp_packet.getlayer(ARP).psrc
        target_ip = arp_packet.getlayer(ARP).pdst
        arp_table_sender = reversed_arp_table.get(sender_mac)
        arp_table_target = reversed_arp_table.get(target_mac)

        # The sender host is spoofing an exiting MAC associated with another IP 
        if (sender_mac == self.arp_table.get(arp_table_sender) and sender_ip != arp_table_sender and sender_mac != self.net.get('announce_mac')):
            return 1

        # The destination host is spoofing an exiting MAC associated with another IP 
        elif (target_mac == self.arp_table.get(arp_table_target) and sender_ip != arp_table_target and target_mac != self.net.get('announce_mac')):
            return 2

        # Add sender host IP, cause sender host MAC is valid and he's not in the ARP table
        elif sender_mac != self.net.get('announce_mac') and sender_ip not in self.arp_table.keys():
            self.arp_table[sender_ip] = sender_mac
            return 0
        
        # Add destination host IP, cause destination host MAC is valid and he's not in the ARP table
        elif target_mac != self.net.get('announce_mac') and target_ip not in self.arp_table.keys():
            self.arp_table[target_ip] = target_mac
            return 0

    def _detect_handshake(self, host_ip, host_mac) -> bool:
        if self.responded_hosts.get(host_ip):
            return True

        syn_packet = IP(dst=host_ip) / TCP()
        syn_ack_packet = sr1(syn_packet, timeout=self.net.get('timeout'))
        icmp_packet = IP(dst=host_ip) / ICMP(type=8)
        icmp_replay = sr1(icmp_packet, timeout=self.net.get('timeout'))

        # The host replay to a SYN request or to a ICMP request
        if syn_ack_packet is not None or (icmp_replay is not None and icmp_replay.haslayer(ICMP) and icmp_replay.getlayer(ICMP).type == 0):
            if host_mac != self.net.get('announce_mac'):
                self.responded_hosts[host_ip] = host_mac
            return True

        return False

    def detect_arp_spoof(self, packet):
        """
            * Summary: Detect if the network are under ARP Spoofing attack if one of the two indicator is true.
            *          Indicator No. 1 is if the delay between two is-at packets less than 2 seconds.
            *          Indicator No. 2 is if 2 IPs share the same MAC address.
            *          Indicator No. 3 is Sending a SYN packet or ICMP request and check if the host responded.

            * Params:  ARP packet to check.
            * Return:  None
        """
        host_ip = packet.getlayer(ARP).psrc
        dst_ip = packet.getlayer(ARP).pdst

        if host_ip != self.host_ip and dst_ip != self.host_ip:
            try:
                self.packet_timestamp.get(host_ip).append(packet.time)
                self.packet_timestamp.get(dst_ip).append(packet.time)

            except AttributeError:
                self.packet_timestamp[host_ip] = [packet.time]
                self.packet_timestamp[dst_ip] = [packet.time]

            # Sender IP is spoofing
            if len(self.packet_timestamp.get(host_ip)) > 1:
                indicator_one = (self.packet_timestamp.get(host_ip)[-1] - self.packet_timestamp.get(host_ip)[-2] < 2)
                self.packet_timestamp.get(host_ip).pop(0)
            else:
                indicator_one = self.packet_timestamp.get(host_ip)[0] > 0

            indicator_two = self._duplicate_mac(packet) == 1
            indicator_three = not self._detect_handshake(host_ip, packet.getlayer(ARP).hwsrc)

            for comb in combinations([indicator_one, indicator_two, indicator_three], 2):
                if all(comb) and packet.getlayer(ARP).hwsrc != self.net.get('announce_mac'):
                    print(Fore.RED + f"[!] {host_ip} spoofing MAC {packet.getlayer(ARP).hwsrc}")
                    break

            # Destination IP is spoofing
            if len(self.packet_timestamp.get(host_ip)) > 1:
                indicator_one = (self.packet_timestamp.get(dst_ip)[-1] - self.packet_timestamp.get(dst_ip)[-2] < 2)
                self.packet_timestamp.get(dst_ip).pop(0)
            else:
                indicator_one = self.packet_timestamp.get(dst_ip)[0] > 0

            indicator_two = self._duplicate_mac(packet) == 2
            indicator_three = not self._detect_handshake(packet.getlayer(ARP).pdst, packet.getlayer(ARP).hwdst)

            for comb in combinations([indicator_one, indicator_two, indicator_three], 2):
                if all(comb) and packet.getlayer(ARP).hwdst != self.net.get('announce_mac'):
                    print(Fore.RED + f"[!] {packet.getlayer(ARP).pdst} spoofing MAC {packet.getlayer(ARP).hwdst}")
                    break


def main():
    if psutil.LINUX and os.getuid() != 0:
        print(Fore.RED + 'Run Program as root' + Fore.RESET)
        exit(1)

    default_interface = 'WiFi' if psutil.WINDOWS else 'eth0'

    arguments = argparse.ArgumentParser()
    arguments.add_argument('-i', '--interface', default=f'{default_interface}', help=f'Detector interface. default is {default_interface}')
    arguments = arguments.parse_args()

    try:
        interface = arguments.interface
        detector = ArpSpoofDetector(interface=interface)
        sniff(lfilter=lambda packet: packet.haslayer(ARP) and detector.is_at_request(packet), prn=detector.detect_arp_spoof)

    except OSError:
        print(Fore.RED + 'Specify an existing interface' + Fore.RESET)
        exit(1)

    except KeyboardInterrupt:
        print(Fore.YELLOW + 'Shutting down detector...' + Fore.RESET)


if __name__ == '__main__':
    main()
