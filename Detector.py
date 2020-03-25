from scapy.all import *
from argparse import ArgumentParser


def arp_filter(packet):
    return ARP in packet and packet.op == 2  # is-at


def ret_hw_src_address(packet):
    return packet.hwsrc


def ret_p_src_address(packet):
    return packet.psrc


def has_duplicates(packets):
    hw_src_address_list = map(ret_hw_src_address,packets)
    p_src_address_list = map(ret_p_src_address, packets)

    for index in range(len(packets)):
        if hw_src_address_list[index] in hw_src_address_list[:index] + hw_src_address_list[index + 1:]\
        and p_src_address_list[index] in p_src_address_list[:index] + p_src_address_list[index + 1:]:
            return True

    return False



def main():
    parser = ArgumentParser(description="Detects if an ARP poisoning attack is occuring:")
    parser.add_argument("-t", "--time", default=60, type=int, help="Time to wait until check for duplicate ARP is-at messages")
    args = parser.parse_args()

    packets = sniff(timeout=10, lfilter=arp_filter)

    if has_duplicates(packets):
        print("You are being poisoned!")



if __name__ == '__main__':
    main()
