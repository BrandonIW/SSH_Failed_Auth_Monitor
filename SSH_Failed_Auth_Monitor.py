import argparse
import logging
import os
import subprocess
import re
import sys

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from time import sleep


class Ip_Node:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.failed_logins = 1

    def __repr__(self):
        return self.ip_address

    @property
    def get_failed_logins(self):
        return self.failed_logins

    def increment(self):
        self.failed_logins += 1

    def reset(self):
        self.failed_logins = 0


def main():
    """ Main function. Builds the Parser for arguments, Logging, and starts Threads """
    args = _build_parser()
    logger = _build_logger()
    ip_queue = deque()
    failed_ips = []

    while True:
        with ThreadPoolExecutor(max_workers=2) as executor:
            ip_address = executor.submit(_read_log, args.logfile, logger).result()
            ip_queue.appendleft(ip_address)

        if ip_queue:
            popped_ip = ip_queue.popleft()

            try:
                ip_node = list(filter(lambda node: str(node) == popped_ip, failed_ips))[0]
                ip_node.increment()
                if ip_node.get_failed_logins >= args.lockout:
                    _lockout(ip_node, args.lockout, args.timeout)
                    logger.warning(f"IP Address {ip_node} has been locked out")

            except IndexError:
                failed_ips.append(Ip_Node(popped_ip))


def _read_log(logfile, logger):
    """ Continual Scanning of log file for any new entries. If new entry matches regex_SSH, extract the IP """
    regex_SSH = re.compile(r'sshd.*Failed\spassword')
    regex_IP = re.compile(r"""\b                                             # Assert Boundary
                              (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.) # Match single valid octet
                              {3}                                            # Match previous 3 times
                              (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)       # Match final ocetet
                              \b                                             # Assert another boundary""", re.VERBOSE)

    def _generator(logfile):
        with open(f'{logfile}', 'r') as file:
            file.seek(0, os.SEEK_END)
            while True:
                line = file.readline()
                if not regex_SSH.search(line):
                    sleep(1)
                    continue
                ip = regex_IP.search(line).group()
                logger.warning(f"Failed SSH Login for IP: {ip}")
                yield ip

    for line in _generator(logfile):
        return line


def _lockout(ip_address, lockout_threshold, timeout):
    pass

def _build_parser():
    """ Build Parser to accept user-defined arguments """
    parser = argparse.ArgumentParser(description="SSH Failed Authentication Monitor")
    required_args = parser.add_argument_group('Required Arguments')
    required_args.add_argument('-l', '--lockout', required=True, type=int, help="Please enter a number for the threshold for "
                                                                                "failed login attempts")
    parser.add_argument('-t', '--timeout', required=False, type=int, default=True,
                        help="Specify the length of time (minutes) the user will "
                             "be locked out if threshold is met (Optional)")
    parser.add_argument('-f', '--logfile', required=False, type=str, default='/var/log/auth.log',
                        help="Specify the log file to monitor for failed SSH Attempts (Defaulted to /var/log/auth.log)")
    args = parser.parse_args()

    return args


def _build_logger():
    """ Build Logger for the program """
    directory = os.path.dirname(os.path.abspath(__file__))
    os.chdir(directory)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    file_handler_info = RotatingFileHandler('../logs/SSH_Auth_info.log', maxBytes=1048576)
    file_handler_warning = RotatingFileHandler('../logs/SSH_Auth_warning.log', maxBytes=1048576)
    file_handler_error = RotatingFileHandler('../logs/SSH_Auth_error.log', maxBytes=1048576)
    stream_handler = logging.StreamHandler(stream=sys.stdout)

    file_handler_info.setLevel(logging.INFO)
    file_handler_warning.setLevel(logging.WARNING)
    file_handler_error.setLevel(logging.ERROR)
    stream_handler.setLevel(logging.DEBUG)

    handlers = [file_handler_info, file_handler_warning, file_handler_error]
    formatter = logging.Formatter('%(asctime)s || %(levelname)s || %(message)s || %(name)s')

    for handler in handlers:
        logger.addHandler(handler)
        handler.setFormatter(formatter)

    return logger


if __name__ == '__main__':
    main()
