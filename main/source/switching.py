"""
Switchstart by 2019-3-18-pop
"""
from argparse import ArgumentParser, Namespace
import sys
from switch_tables.switch import Switch
from switch_tables.switch_table import SwitchTable


def parse_cli() -> Namespace:
    """
    Function to parsing cli args
    Returns: Namespace

    """
    parser = ArgumentParser(description='SWITCH by 2019-3-18-pop')
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
        result += f"\tInvalid ttl: {args.count} <= 1\n"
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

    table = SwitchTable(args.interfaces.split(','), args.ttl, args.count, args.file)
    switch = Switch(table)
    print('SWITCHING')
    switch.start()


if __name__ == "__main__":
    main()
