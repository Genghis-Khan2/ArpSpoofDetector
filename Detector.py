from scapy.all import *
from argparse import ArgumentParser
from arp_table import get_arp_table

hw_addresses = []
p_addresses = []


def arp_filter(packet):
    return ARP in packet and packet.op == 2  # is-at


def check_for_dup(packet):
    if hw_addresses.index(packet[ARP].hwsrc) == p_addresses.index(packet[ARP].psrc):
        raise ValueError
    hw_addresses.append(packet[ARP].hwsrc)
    p_addresses.append(packet[ARP].psrc)

def check_for_dup2(packet): #Pun intended!
    for entry in get_arp_table():
        if entry['HW address'] == packet[ARP].hwsrc and packet[ARP].psrc != entry['IP address']:
            raise ValueError

def main():
    parser = ArgumentParser(description="Detects if an ARP poisoning attack is occuring")
    parser.add_argument("-t", "--time", default=20, type=int, help="Time to wait until check for duplicate ARP is-at messages")
    args = parser.parse_args()

    try:
        packets = sniff(timeout=args.time, lfilter=arp_filter, prn=check_for_dup)
    except ValueError:
        print("You are being poisoned!")



if __name__ == '__main__':
    main()
