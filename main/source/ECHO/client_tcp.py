"""
client-tcp by 2019-3-18-pop
"""

import socket
import threading
import sys
import os
from argparse import ArgumentParser, Namespace
from scapy.all import get_if_addr
from checker import check_ip, check_port


class TCPClient:
    """
    TCPClient for ECHO-TCP-Client
    Contains:
            -server_ip: ip address server : str
            -host_port: TCP port for host(client) : int
            -server_port: TCP port for server : int
    """

    def __init__(self, server_ip: str, host_port: int, server_port: int):
        self.hostname = socket.gethostname()
        self.client_socket = socket.socket()
        host_ip = get_if_addr('ens33')

        try:
            self.client_socket.bind((host_ip, host_port))
            self.client_socket.connect((server_ip, server_port))
        except OSError as err:
            if err.errno == 107:
                print('Unable to connect to server')
            elif err.errno == 111:
                print("Connection refused")
            elif err.errno == 98:
                print("Address in use")
            else:
                print(f"Something wrong with connection: {err.errno}")
            sys.exit(2)

        self.connected = True
        self.all_data = ''
        self.listener_th = None

    def listen(self) -> None:
        """
        Listen traffic for TCP segments for the client
        """
        while self.connected:
            try:
                data = self.client_socket.recv(1024).decode()
                print(f"<<< {data}")
                print('>>>', end='')
            except OSError:
                return
        print("Disconnected from server...")
        self.client_socket.close()
        self.listener_th = None

    def send(self, msg: str) -> None:
        """
        Function to send msg to server
        """
        if self.connected:
            if msg == "stop":
                print('Stop the connection..')
                self.connected = False
            try:
                self.client_socket.send(msg.encode())
            except OSError as err:
                if err.errno == 32:
                    print("Can't send to server")
                if err.errno == 9:
                    pass
                else:
                    print(f"Something wrong with connection: {err.errno}")
                sys.exit(2)
        else:
            print("Client is disconnected")

    def start(self) -> None:
        """
        Function to start listen traffic fot TCP segments
        """
        self.listener_th = threading.Thread(target=self.listen)
        self.listener_th.start()


def check_args(args: Namespace) -> str:
    """
    Function to check args of cli
    """
    result = ""
    server_port = args.server_port
    host_port = args.host_port
    server_ip = args.ip

    if args.file and os.path.isfile(args.file):
        with open(args.file, 'r') as file:
            try:
                line = file.readline().split(' ')
                server_port, host_port, server_ip = int(line[0]), int(line[1]), line[2]
            except ValueError as err:
                print(f"Invalid value in {args.file} : {line} : {err}")
                sys.exit(1)
    if not host_port or not check_port(host_port):
        result += f"\tHost port is invalid: {host_port}\n"
    if not server_port or not check_port(server_port):
        result += f"\tServer port is invalid: {server_port}\n"
    if not server_ip or not check_ip(server_ip):
        result += f"\tIP is invalid: {server_ip}\n"

    return result


def parsing() -> Namespace:
    """
    Function to parse args from cli
    """
    parser = ArgumentParser()
    parser.add_argument(
        '-sp', '--server_port',
        type=int,
        help='Server port')
    parser.add_argument(
        '-hp', '--host_port',
        type=int,
        help='Host port')
    parser.add_argument(
        '-ip',
        type=str,
        help='Server ip')
    parser.add_argument(
        '-f', '--file',
        type=str,
        help='Configure filepath')
    args = parser.parse_args()
    return args


def main() -> None:
    """
    Function to initialization TCP connection
    """
    args = parsing()
    log = check_args(args)

    if log:
        print("Error:")
        print(log)
        sys.exit(1)

    if args.file and os.path.isfile(args.file):
        with open(args.file, 'r') as file:
            try:
                line = file.readline().split(' ')
                server_port, host_port, server_ip = int(line[0]), int(line[1]), line[2]
            except ValueError as err:
                print(f"Invalid value in {args.file} : {line} : {err}")
                sys.exit(1)
    else:
        server_port, host_port, server_ip = args.server_port, args.host_port, args.ip

    tcp_client = TCPClient(server_ip, host_port, server_port)
    try:
        tcp_client.start()
        print(">>> ", end='')

        while tcp_client.connected:
            msg = input()

            tcp_client.send(msg)
    except KeyboardInterrupt:
        print("Extra stopping")
        tcp_client.client_socket.close()


if __name__ == '__main__':
    main()
