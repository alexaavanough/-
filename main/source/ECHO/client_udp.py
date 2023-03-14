"""
UDP-client by 2019-3-18-pop
"""
import sys
import socket
import os
from argparse import ArgumentParser, Namespace
from scapy.all import get_if_addr
from checker import check_port, check_ip

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def start_client_udp(server_ip: str, server_port: int, host_port: int) -> None:
    """
    Start UDP receiving
    """
    addr = (server_ip, server_port)
    try:
        udp_socket.bind((get_if_addr('ens33'), host_port))
    except OSError as err:
        print(f"Something wrong with connection: {err.errno}")
        sys.exit(1)
    print('>>>: ', end='')
    while True:
        send_data = input()
        udp_socket.sendto(send_data.encode(), addr)
        received_data = udp_socket.recvfrom(1024)[0].decode()
        print("Received from server: " + received_data)
        print('>>>: ', end='')
        if send_data == 'stop':
            print("Finishing")
            break


def check_args(args: Namespace) -> str:
    """
    Function to check args of cli
    """
    result = ""
    server_port = args.server_port
    host_port = args.client_port
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
        '-cp', '--client_port',
        type=int,
        help='Client port')
    parser.add_argument(
        '-ip',
        type=str,
        help='Server ip')
    parser.add_argument(
        '-f', '--file',
        type=str,
        help='Configure filepath'
    )
    return parser.parse_args()


def main() -> None:
    """
    Function to initialization UDP receiving
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
        server_port, host_port, server_ip = args.server_port, args.client_port, args.ip

    try:
        start_client_udp(server_ip, server_port, host_port)
    except KeyboardInterrupt:
        print("EXTRA stopping")
        udp_socket.close()


if __name__ == '__main__':
    main()
