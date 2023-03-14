"""
Modification of traffic by 2019-3-18-pop
"""

from argparse import ArgumentParser, Namespace
import sys
import os
from switch_tables.switch import Switch
from switch_tables.switch_table import SwitchTable


def parse_cli() -> Namespace:
    """
    Function to parsing cli args
    Returns: Namespace

    """
    parser = ArgumentParser(description='MODIFICATION_TRAFFIC by 2019-3-18-pop')
    parser.add_argument(
        "-t", "--ttl",
        default=300,
        type=int,
        help="Time to live of note in the table"
    )
    parser.add_argument(
        '-i', '--interfaces',
        default=None,
        type=str,
        help="List of interfaces of the switch: <inter1>,<inter2>,<...>"
    )
    parser.add_argument(
        '-c', '--count',
        default=2,
        type=int,
        help="Count of ports"
    )
    parser.add_argument(
        '-if', '--input',
        default='',
        type=str,
        help="Input file with rules"
    )
    parser.add_argument(
        '-ct', '--change',
        default='',
        type=int,
        help="Change TTL"
    )
    parser.add_argument(
        '-cl', '--change_log',
        default='',
        type=str,
        help="Change log"
    )
    parser.add_argument(
        '-rl', '--reject_log',
        default='',
        type=str,
        help="Reject log TTL"
    )
    return parser.parse_args()


def check_args(args: Namespace) -> str:
    """
    Function to check args of cli
    """
    result = ""
    if args.interfaces is None:
        result += "\tEmpty list of interfaces\n"
    if args.count <= 1:
        result += f"\tInvalid count of ports: {args.count} <= 1\n"
    if args.ttl <= 0:
        result += f"\tInvalid ttl: {args.count} <= 0\n"
    if args.change <= 0:
        result += f"\tInvalid change ttl: {args.change} <= 0\n"
    if not os.path.isfile(args.input):
        result += f"\tInvalid input file with rules: {args.input}\n"
    if not os.path.isfile(args.change_log):
        result += f"\tInvalid log for changing: {args.change_log}\n"
    if not os.path.isfile(args.reject_log):
        result += f"\tInvalid log for rejection: {args.reject_log}\n"
    return result


def main() -> None:
    """
    Function to starting Switch with cli args
    Returns: None

    """
    args = parse_cli()
    log = check_args(args)
    if log:
        print(f"Error:\n{log}")
        sys.exit(1)

    table = SwitchTable(args.interfaces.split(','), args.ttl, args.count, args.input, args.change, args.reject_log,
                        args.change_log)
    switch = Switch(table)
    print('MODIFICATION')
    try:
        switch.start()
    except KeyboardInterrupt:
        print('Stop modification switch')


if __name__ == "__main__":
    main()
