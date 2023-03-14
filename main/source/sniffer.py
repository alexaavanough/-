"""
SNIFFER by 2019-3-18
"""
import sys
from argparse import ArgumentParser, Namespace
from datetime import datetime
from termcolor import colored, cprint
from scapy.layers.inet import Ether, IP, ICMP, UDP, icmptypes
import scapy.all as scapy


class Sniffer:
    """
    Class for sniffer for 1 interface.
    Contains:
                - num_of_packets - num of caught packets : int
                - interface - net interface for sniffing : str
                - interactive - working mode of sniffer : bool (default: True)
                - switch - link to switch if sniffer works in hide mode : Switch (default: None)
    """

    def __init__(self, interface: str, interactive=True, switch=None):
        self.num_of_packets: int = 0
        self.interface: str = interface
        self.interactive: bool = interactive
        self.switch = switch

    def start(self) -> None:
        """
            Function to start sniffing
            Returns: none

        """

        try:
            if self.interactive:
                print("---Starting_interactive_sniffing---")
                scapy.sniff(iface=self.interface, store=False, prn=self.receive_interactive)
            else:
                scapy.AsyncSniffer(iface=self.interface, store=False,
                                   prn=self.receive_sneaky).start()
        except OSError:
            print(f"Can't find this device: {self.interface}")
            sys.exit(1)

    def receive_interactive(self, packet: scapy.packet) -> None:
        """
        Function to print information about caught packets
        Args:
            packet: caught packet
        Returns: none

        """
        print(f"Пакет <{colored(str(datetime.now()), color='yellow')}>: ")
        if packet.haslayer(Ether):
            self.num_of_packets += 1
            cprint("\tinfo Ethernet", color='cyan')
            print(f"\t\tПорядковый номер пакета: {str(self.num_of_packets)}")
            print(f"\t\tАдрес отправителя: {packet['Ethernet'].src}")
            print(f"\t\tАдрес полуECHO-сервереля: {packet['Ethernet'].dst}")
            print(f"\t\tВложенный протокол: {scapy.ETHER_TYPES[packet['Ethernet'].type]}")
            print(f"\t\tРазмер данных в байтах: {len(packet.payload)}")
            print()
        if packet.haslayer(IP):
            cprint("\tinfo IPv4", color='magenta')
            print(f"\t\tАдрес источника: {packet['IP'].src}")
            print(f"\t\tАдрес назначения: {packet['IP'].dst}")
            print(f"\t\tЗначение поля TTL: {str(packet['IP'].ttl)}")
            print(f"\t\tВложенный протокол: {scapy.IP_PROTOS[packet['IP'].proto]}")
            print(f"\t\tРзамер данных в байтах: {str(packet['IP'].len)}")
            print()
        if packet.haslayer(ICMP):
            cprint("\tinfo ICMP", color='green')
            print(f"\t\tТип: {icmptypes[packet['ICMP'].type]}")
            print(f"\t\tКод: {str(packet['ICMP'].code)}")
            print(f"\t\tРазмер данных в байтах: {str(packet['ICMP'].length)}")
            print()
        if packet.haslayer(UDP):
            cprint("\tinfo UDP", color='yellow')
            print(f"\t\tПорт источника: {str(packet['UDP'].sport)}")
            print(f"\t\tПорт назначения: {str(packet['UDP'].dport)}")
            print(f"\t\tРазмер данных байтах: {str(packet['UDP'].len)}")
            print()
        print("-----" * 13)

    def receive_sneaky(self, packet: scapy.packet) -> None:
        """
        Function to receive packets for Switch
        Args:
            packet: caught packet
        Returns: None

        """
        if self.switch:
            self.switch.receive(packet, self.interface)


def parsing() -> Namespace:
    """
    Function to parsing CLI
    Returns: cli args

    """
    parser = ArgumentParser(description=colored("Sniffer by 2019-3-18", color='red'))
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default="lo",
        help="One of interfaces: " + colored(' '.join(scapy.get_if_list()), color='cyan')
    )
    return parser.parse_args()


def main() -> None:
    """
    main function
    Returns: none

    """
    try:
        sniffer = Sniffer(parsing().interface)
        sniffer.start()
    except KeyboardInterrupt:
        print("Stop sniffing")


if __name__ == '__main__':
    main()
