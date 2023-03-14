"""
UDP-server by 2019-3-18-pop
"""
from argparse import ArgumentParser, Namespace
import sys
import socket
import os
from scapy.all import get_if_addr
from checker import check_port

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def parsing():
    """
    Function to parse args from cli
    """
    parser = ArgumentParser()
    parser.add_argument(
        '-p', '--port',
        type=int,
        help='Server port')
    parser.add_argument(
        '-f', '--file',
        type=str,
        help="Configure filepath"
    )
    return parser.parse_args()


def check_args(args: Namespace) -> str:
    """
    Function to check args of cli
    """
    result = ""
    port = args.port

    if args.file and os.path.isfile(args.file):
        with open(args.file, 'r') as file:
            try:
                line = file.readline().split(' ')
                port, count = line[0], line[1]
            except ValueError as err:
                print(f"Invalid value in {args.file} : {line} : {err}")
                sys.exit(1)
    if not port or not check_port(port):
        result += f"\tServer port is invalid: {port}"

    return result


def start_server_udp(port: int) -> None:
    """
    Start UDP receiving
    """
    try:
        udp_socket.bind((get_if_addr('ens33'), port))
    except OSError as err:
        print(f"Something wrong with connection: {err.errno}")
        sys.exit(1)
    print('Server start')
    while True:
        msg, addr = udp_socket.recvfrom(1024)
        msg = msg.decode()
        print('From ' + addr[0] + ' on port ' + str(addr[1]) + ', received: ' + msg)
        udp_socket.sendto(msg.encode(), addr)
        if msg == 'stop':
            break

    udp_socket.close()


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
                line = file.readline()
                port = int(line)
            except ValueError as err:
                print(f"Invalid value in {args.file} : {line} : {err}")
                sys.exit(1)
    else:
        port = args.port

    try:
        start_server_udp(port)
    except KeyboardInterrupt:
        print('EXTRA stopping...')
        udp_socket.close()


if __name__ == '__main__':
    main()
