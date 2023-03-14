"""
SWITCH by 2019-3-18-pop
"""
import sys
from threading import Thread, Timer, Lock
from datetime import datetime
import scapy.all as scapy
from sniffer import Sniffer

scapy.conf.verb = 0


class Switch:
    """
    Switch class
    Contains:
                -table: object of SwitchTable : SwitchTable
                -interfaces: contains time of working : dict
                -sniffers: contains working sniffers for this switch : list
                -mac_ignore: macs of switch interfaces : list
                -lock: lock for threading
    """

    def __init__(self, table):
        self.__table = table
        self.__interfaces_info = {}
        try:
            self.mac_ignore = [scapy.get_if_hwaddr(i) for i in self.__table['interfaces']]
        except OSError:
            print('One of interfaces is invalid')
            sys.exit(1)
        for interface in self.__table['interfaces']:
            self.__interfaces_info[interface] = [0, 0, 0]
        self.__lock = Lock()

    def start(self) -> None:
        """
        Function to starting switch and sniffing
        Returns: None

        """
        Thread(target=self.__timer_table).start()
        for interface in self.__table['interfaces']:
            sniffer = Sniffer(interface, False, self)
            sniffer.daemon = True
            sniffer.start()

    def receive(self, packet: scapy.packet, interface: str) -> None:
        """
        Function to receive packets
        Args:
            packet: received packet
            interface: interface
        Returns: None

        """
        # trying to control threads

        if packet.haslayer("Ethernet"):
            start_time = datetime.now()
            with self.__lock:
                table = self.__table['table']

            src = packet["Ethernet"].src
            dst = packet["Ethernet"].dst

            if src not in self.mac_ignore and dst not in self.mac_ignore:

                port_to_add = []
                port_to_send = []
                interface_of_packet = None
                with self.__lock:
                    source = self.__table.find(src)
                    target = self.__table.find(dst)

                if source is None:
                    for port in table:
                        if table[port][0] == '-':
                            if interface == table[port][2]:
                                port_to_add.append(port)
                    if port_to_add:
                        with self.__lock:
                            self.__table.add(port_to_add[0], src)
                        interface_of_packet = table[port_to_add[0]][2]
                else:
                    interface_of_packet = table[source][2]
                    with self.__lock:
                        self.__table.add(source)

                if target is None:
                    for port in table:
                        if interface != table[port][2]:
                            port_to_send.append(table[port][2])
                else:
                    port_to_send = [table[target][2]]

                if interface_of_packet == interface:
                    with self.__lock:
                        if self.__table.change:
                            packet = self.__table.modify(packet)

                    if packet:
                        Switch.__send(packet, port_to_send, interface)
                    end_time = datetime.now()

                    self.__time(start_time, end_time, interface)

    @staticmethod
    def __send(packet: scapy.packet, port_to_send: list, interface_of_packet) -> None:
        """
        Function to send packet
        Args:
            packet: packet to send
            port_to_send: list of interfaces which will be used for sending

        Returns: None

        """
        port_to_send = set(port_to_send)
        for interface in port_to_send:
            if interface_of_packet != interface:
                scapy.sendp(packet, iface=interface)

    def __timer_table(self) -> None:
        """
        Function to starting switch's timer
        Returns: None

        """
        timer = None
        while True:
            if timer is None or not timer.is_alive():
                timer = Timer(1, self.__table.refresh)
                timer.daemon = True
                timer.start()
                self.__table.print(self.__interfaces_info)

    def __time(self, start: datetime, end: datetime, interface: str) -> None:
        """
        Function to update info about interface
        Args:
            start: start time
            end: end time
            interface: working interface

        Returns: None
        """
        time_work = (end.microsecond - start.microsecond) / 100000

        self.__interfaces_info[interface][2] += 1
        self.__interfaces_info[interface][0] = round((self.__interfaces_info[interface][0]
                                                      + time_work)
                                                     / (self.__interfaces_info[interface][2])
                                                     , 4)
        self.__interfaces_info[interface][1] = round(max(self.__interfaces_info[interface][1],
                                                         time_work), 4)
