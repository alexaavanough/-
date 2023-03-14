"""
Module for checking ip and port
"""


def check_ip(ip: str) -> bool:
    """
    Function to check ip
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False

    for part in parts:
        try:
            if int(part) < 0 or int(part) > 255:
                return False
        except ValueError:
            return False

    return True


def check_port(port: int) -> bool:
    """
    Function for check port
    """
    return 0 <= int(port) <= 65535 if type(port) else False
