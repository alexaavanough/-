"""
SWITCH_TACLE & modification by 2019-3-18-pop
"""
import prettytable as pt
from scapy.layers.inet import IP, TCP, Ether, UDP
from scapy.all import wrpcap
from os import system
import dpkt


class SwitchTable:
    """
    Table class
    Contains:
                -table: {port: [mac, ttl, interface]} : dict
                -ttl: time to live for a note in table : int
    """

    def __init__(self, interfaces: list, ttl: int, count: int, filepath=None, change_time=None, reject_log=None,
                 change_log=None):
        self.table = {}
        self.ttl = ttl

        self.change = None
        if filepath:
            self.read(filepath)
        self.mac = None

        self.change_time = change_time
        self.rlog = reject_log
        self.clog = change_log

        for i in range(0, count):
            self.table[i] = ['-', '-', interfaces[i % len(interfaces)]]

    def add(self, port: int, mac=None) -> None:
        """
        Function to add/refresh a note
        Args:
            port: int
            mac: str

        Returns: None
        """
        if mac:
            self.table[port][0] = mac

        self.table[port][1] = self.ttl

    def print(self, interfaces_working: dict) -> None:
        """
        Function to print mac-table
        Args:
            interfaces_working: info about working interfaces : dict
        Returns: None

        """
        ptable_switch = pt.PrettyTable()
        ptable_interfaces = pt.PrettyTable()

        ptable_switch.field_names = ['PORT', 'MAC', 'TTL', 'INTERFACE']
        ptable_interfaces.field_names = ['INTERFACE', 'AVERAGE', 'MAX', 'COUNT']

        for port in self.table:
            ptable_switch.add_row([port, *self.table[port]])

        for interface in interfaces_working:
            ptable_interfaces.add_row([interface, interfaces_working[interface][0] / 100000,
                                       interfaces_working[interface][1] / 100000,
                                       interfaces_working[interface][2]])

        system('clear||cls')
        print("SWITCH_TABLE")
        print(ptable_switch)
        print('WORKING_INFO')
        print(ptable_interfaces)

    def refresh(self) -> None:
        """
        Function to refresh
        Returns: None

        """
        for port in self.table:
            if self.table[port][1] != '-':
                self.table[port][1] -= 1

                if self.table[port][1] <= 0:
                    self.table[port][0] = self.table[port][1] = '-'

    def __getitem__(self, item: str):
        if item == 'table':
            return self.table
        if item == 'interfaces':
            result = set()
            for port in self.table:
                result.add(self.table[port][2])
            return result
        if item == 'ttl':
            return self.ttl
        return None

    def find(self, mac: str):
        """
        Function to find interface using mac
        Args:
            -mac: str
        """
        for port in self.table:
            if self.table[port][0] == mac:
                return port

    @staticmethod
    def sum(packet):
        packet[IP].ttl = 255
        del packet[1].chksum
        del packet[2].chksum
        packet = packet.__class__(bytes(packet))
        return packet

    def modify(self, packet):
        """
        Function to modify packet by rules (for ModificationTable)
        """
        if packet.haslayer[IP]:
            if packet.haslayer(TCP):
                if packet[IP].src == self.change['B'][0] and packet[IP].dst == self.change['C'][0] \
                        and packet[TCP].sport == self.change['B'][1] and packet[TCP].dport == self.change['C'][1]:
                    packet[IP].src = self.change['A'][0]
                    packet[TCP].sport = self.change['A'][1]
                    self.mac = packet[Ether].src

                if packet[IP].src == self.change['C'][0] and packet[IP].dst == self.change['A'][0] \
                        and packet[TCP].sport == self.change['C'][1] and packet[TCP].dport == self.change['A'][1]:
                    packet[IP].drc = self.change['B'][0]
                    packet[TCP].dport = self.change['B'][1]
                    packet[Ether].dst = self.mac

                packet[IP].ttl = self.change_time
                if self.clog:
                    with open(self.clog, 'wb') as file:
                        pacp = dpkt.pcap.Writer(file)
                        pacp.writepkt(packet)

                return SwitchTable.sum(packet)

            if packet.haslayer(UDP):
                ALLOW_IPS = ('192.168.3.17', '192.168.3.51')

                if not packet[IP].src in ALLOW_IPS:
                    if self.rlog:
                        with open(self.rlog, 'wb') as file:
                            pacp = dpkt.pcap.Writer(file)
                            pacp.writepkt(packet)
                    return None

        return packet

    def read(self, filepath):
        with open(filepath, 'r') as file:
            line = file.readline().split(' ')
            self.change = {'B': [line[0], line[1]], 'A': [line[2], line[3]], 'C': [line[4], line[5]]}
