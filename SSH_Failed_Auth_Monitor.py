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

# TODO: Log files are going to the right place on Windows? Mac? Can we test that?


# Thread 1: Continually parsing through log file. When it finds the log, it will extract the IP address and return 
# Main Thread: 

class Ip_Node:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.failed_logs = 0
    
    def increment(self):
        self.failed_logs += 1
        
        
def main():
    """ Main function. Builds the Parser for arguments, Logging, and starts Threads """
    directory = os.path.dirname(os.path.abspath(__file__))
    os.chdir(directory)

    args = _build_parser()
    logger = _build_logger()

    while True:
        with ThreadPoolExecutor(max_workers=2) as executor:
            ip_address = executor.submit(_read_log, args.logfile, logger).result()
            executor.submit(_monitor_auth, args.lockout, args.timeout, ip_address)


def _read_log(logfile, logger):
    regex_SSH = re.compile(r'sshd.*Failed\spassword')
    regex_IP = re.compile(r"""\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)
                               {3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b""", re.VERBOSE)

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


def _monitor_auth(threshold, timeout, ip_address):
    ip_stack = deque()
    # sleep(1)
    # print(log_stack)
    # for line in log_stack:
    #     print(line.result())

def _build_parser():
    """ Build Parser to accept user-defined arguments """
    parser = argparse.ArgumentParser(description="SSH Failed Authentication Monitor")
    parser.add_argument('-l', '--lockout', required=True, type=int, help="Please enter a number for the threshold for "
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
