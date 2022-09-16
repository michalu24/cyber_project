import socket

import scapy.all as scapy
from socket import *
import time
import netifaces as ni


def check_network_address():
    ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
    netmask = ni.ifaddresses('eth0')[ni.AF_INET][0]['netmask']
    return ip, netmask

def convert_netmask_to_CIDR(netmask: str):
    list_mask = netmask.split(".")
    processing = list()
    for octet in list_mask:
        processing.append(str(bin(int(octet))).count("1"))
    return sum(processing)

def provide_range(ip_address: str, netmask):
    converted_CIDR = convert_netmask_to_CIDR(netmask)
    list_elements = ip_address.split(".")
    list_elements.pop()
    list_elements.append(f"0/{converted_CIDR}")
    return ".".join(list_elements)

def scan_for_active_ips():
    request = scapy.ARP()
    address = check_network_address()
    print(f"Your IP_ADDRESS is : {address[0]}")
    print(f"Your NETMASK is : {address[1]}")
    request.pdst = provide_range(str(address[0]), str(address[1]))
    broadcast = scapy.Ether()

    broadcast.dst = 'ff:ff:ff:ff:ff:ff'

    request_broadcast = broadcast / request
    clients = scapy.srp(request_broadcast, timeout=10, verbose=1)[0]
    results = []
    print("ACTIVE DEVICES:")
    print("===========================================")
    for element in clients:
        print(element[1].psrc + "	 " + element[1].hwsrc)
        results.append(element[1].psrc)
    print("===========================================")
    return results

def ports_scan(ips_list: []):

    print("ACTIVE PORTS FOR IPS")
    print("===========================================")
    ports = {}
    for i in ips_list:
        startTime = time.time()
        target = i
        t_IP = gethostbyname(target)
        print('Starting scan on host: ', t_IP)

        active_ports = []
        for i in range(0, 500):
            s = socket(AF_INET, SOCK_STREAM)
            s.timeout
            conn = s.connect_ex((t_IP, i))
            if (conn == 0):
                print('Port %d: OPEN' % (i,))
                active_ports.append(i)
            s.close()
        ports[i] = active_ports
        print('Time taken:', time.time() - startTime)

    print("===========================================")
    return ports


def banner_grab(ip_address, port):
    try:
        s = socket.socket()
        s.connect((ip_address, port))
        banner = s.recv(1024)
        s.close()
        return banner.decode()
    except:
        return ''

if __name__ == '__main__':
    results = scan_for_active_ips()
    ports = ports_scan(results)
