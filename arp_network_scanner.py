#!usr/bin/env python

import scapy.all as scapy
import argparse


# get_arguments() function is used to get the arguments from the user
def get_arguments():

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Interface to find the target IP/ IP range")

    args = parser.parse_args()

    # If the user doesn't specify the target, then the program will throw an error
    if not args.target:
        parser.error("[-] Please specify a target, use --help for more info")
    return args


# scan() function is used to scan the network
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)  # pdst is the destination IP address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # ff:ff:ff:ff:ff:ff is the broadcast MAC address
    arp_request_broadcast = broadcast/arp_request  # Combining the two packets together
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    # Looping through the answered_list and appending the IP and MAC address to the clients_list
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


# print_result() function is used to print the result
def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in results_list:
        print(client["IP"] + "\t\t" + client["MAC"])


args = get_arguments()
scan_result = scan(args.target)
print_result(scan_result)
