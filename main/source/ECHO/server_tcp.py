"""
TCP-server by 2019-3-18-pop
"""
import socket
import sys
import os
import select
from argparse import ArgumentParser, Namespace
from scapy.all import get_if_addr
from checker import check_port


class TCPServer:
    """
    TCP server for TCP ECHO server
    Contains:
            -server_ip: ip address of server : str
            -port: server port : int
    """

    def __init__(self, port: int, count: int):
        self.server_ip = get_if_addr('ens33')
        self.port = port
        try:
            self.server_socket = socket.socket()
            self.server_socket.bind((self.server_ip, port))
        except OSError as err:
            if err.errno == 107:
                print('Unable to connect to server')
            elif err.errno == 111:
                print("Connection refused")
            else:
                print("Something wrong with connection")
            sys.exit(2)

        self.num_of_clients = 0
        self.count = count
        self.inputs = [self.server_socket]
        self.outputs = []
        self.messages = {}
        self.clients = []

    def accept_messages(self) -> None:
        """
        Start function
        """
        print("Server started")
        self.server_socket.listen(self.count)
        while True:
            reads, send, excepts = select.select(self.inputs, self.outputs, self.inputs)
            for connection in reads:
                if connection == self.server_socket:
                    new_connection, new_addr = connection.accept()
                    self.inputs.append(new_connection)
                    self.clients.append(new_connection)
                    new_connection.setblocking(False)
                    self.num_of_clients += 1
                    print("Connected " + str(self.num_of_clients) + " client(s)")
                else:
                    data = connection.recv(1024).decode()
                    if not data:
                        print("Client " + connection.getpeername()[0] + " disconnected with"
                                                                        " error")
                        if connection in self.outputs:
                            self.outputs.remove(connection)
                            del self.messages[connection]
                        self.inputs.remove(connection)
                        self.clients.remove(connection)
                        reads.remove(connection)
                        connection.close()
                        self.num_of_clients -= 1
                        del connection
                        print("Connected " + str(self.num_of_clients) + " client(s)")

                    elif data != "stop":
                        for receiver in self.clients:
                            if receiver is not connection:
                                self.outputs.append(receiver)
                        for receiver in self.clients:
                            if receiver != connection:
                                if self.messages.get(receiver, None):
                                    self.messages[receiver].append(data)
                                else:
                                    self.messages[receiver] = [data]
                        print("From client " + str(connection.getpeername()[0])
                              + " on port " + str(connection.getpeername()[1])
                              + "\treceived: " + data)

                    else:
                        connection.send("stop".encode())
                        print('Client ' + connection.getpeername()[0] + ' disconnected...')
                        if connection in self.outputs:
                            self.outputs.remove(connection)
                            del self.messages[connection]
                        self.inputs.remove(connection)
                        self.clients.remove(connection)
                        reads.remove(connection)
                        connection.close()
                        self.num_of_clients -= 1
                        del connection
                        print("Connected " + str(self.num_of_clients) + " client(s)")

            for connection in send:
                msg = self.messages.get(connection, None)
                if msg:
                    connection.send(msg.pop(0).encode())
                else:
                    self.outputs.remove(connection)

            for connection in excepts:
                print('Client has gone...')
                self.inputs.remove(connection)
                if connection in self.outputs:
                    self.outputs.remove(connection)
                connection.close()
                self.clients.remove(connection)
                del self.messages[connection]


def check_args(args: Namespace) -> str:
    """
    Function to check args of cli
    """
    result = ""
    port = args.port
    count = args.count

    if args.file and os.path.isfile(args.file):
        with open(args.file, 'r') as file:
            line = file.readline().split(' ')
            try:
                port, count = int(line[0]), line[1]
            except ValueError as err:
                print(f"Invalid value in {args.file} : {line} : {err}")
                sys.exit(1)
    if not port or not check_port(port):
        result += f"\tServer port is invalid: {port}"
    if count < 1:
        result += f"The count of users is invalid: {count} < 1"

    return result


def parsing() -> Namespace:
    """
    Function to parse args from cli
    """
    parser = ArgumentParser()
    parser.add_argument(
        '-p', '--port',
        type=int,
        help='server port')
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=10,
        help='count of users')
    parser.add_argument(
        '-f', '--file',
        type=str,
        help='Filepath to configure file'
    )
    return parser.parse_args()


def main():
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
            line = file.readline().split(' ')
            port, count = line[0], line[1]
    else:
        port, count = args.port, args.count

    tcpserver = TCPServer(port, count)
    try:
        tcpserver.accept_messages()
    except KeyboardInterrupt:
        print("EXTRA stopping...")
        tcpserver.server_socket.close()


if __name__ == '__main__':
    main()
