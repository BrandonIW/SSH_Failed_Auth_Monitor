import argparse
import logging
import os
import queue
import re
import subprocess
import sys

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from time import sleep


class Ip_Node:
    """ An Object representing each IP that fails to auth. Methods associated with the object allow us to keep track
    of its state, including its IP, number of failed logins, and when last it failed a login """

    def __init__(self, ip_address, _time_added=datetime.now()):
        self.ip_address = ip_address
        self._failed_logins = 1
        self.time_added = _time_added
        self.is_blocked = False

    def __repr__(self):
        return self.ip_address

    @property
    def failed_logins(self):
        return self._failed_logins

    @failed_logins.setter
    def failed_logins(self, value):
        self._failed_logins = value

    @property
    def time_added(self):
        return self._time_added

    @time_added.setter
    def time_added(self, time):
        self._time_added = time

    def increment(self):
        self._failed_logins += 1


def main():
    """ Builds a parser to take in arguments, and a logger. Then creates 2 threads, one to continually monitor the
    logfile in real-time, and one to continually monitor the difference between the timeout (if specified)
    and the Ip_Node's ._time_added property. Creates a Queue to pass the list of Ip_Nodes that have failed auth. between
    threads """

    args = _build_parser()
    logger = _build_logger()
    q = queue.Queue()

    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(_process_ips, args, logger, q)
        executor.submit(_check_timeout, args.timeout, logger, q)


def _process_ips(args, logger, q):
    """ Continually loops over _read_logs. _read_logs generator will pause until the regex matches, which returns an
    IP address. Checks if that IP address is already in our list of known-failed IPs. If so, increment _failed_logins
    and update that Node's _time_added property. If not, create a new Node for this IP and add to the Queue """

    ip_failed_auth_list = []

    while True:
        ip_address = _read_log(args.logfile, logger)

        try:
            ip_node = list(filter(lambda node: str(node) == ip_address, ip_failed_auth_list))[0]
            ip_node.increment()
            ip_node.time_added = datetime.now()
            logger.info(f"IP Failed to Login: {ip_node} | Updated Date {datetime.now()} | "
                        f"Times Failed {ip_node.failed_logins}")
            if ip_node.failed_logins == args.lockout:
                ip_node.is_blocked = True
                _lockout(ip_node)
                logger.error(f"IP Address {ip_node} has been locked out")

        except IndexError:
            new_node = Ip_Node(ip_address)
            ip_failed_auth_list.append(new_node)
            q.put(new_node)
            logger.info(f"New IP Added: {ip_address} | Date Added {datetime.now()}")


def _read_log(logfile, logger):
    """ Continual Scanning of log file for any new entries. If new entry matches regex_SSH, extract the IP """
    regex_SSH = re.compile(r'sshd.*Failed\spassword')
    regex_IP = re.compile(r"""\b                                             # Assert Boundary
                               (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.) # Match single valid octet
                               {3}                                            # Match previous 3 times
                               (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)       # Match final ocetet
                               \b                                             # Assert another boundary""",
                          re.VERBOSE)

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


def _lockout(ip_address, timeout_reached=False):
    if timeout_reached:
        subprocess.run(["iptables", "-D", "INPUT", "-s", f"{ip_address}", "-p", "tcp", "--dport", "22", "-j", "DROP"])
        return
    subprocess.run(["iptables", "-A", "INPUT", "-s", f"{ip_address}", "-p", "tcp", "--dport", "22", "-j", "DROP"])


def _check_timeout(timeout, logger, q):
    """ Continually checks the shared Queue for new IP addresses. Times out after 5 seconds. If a new IP address fails
    login, it will be passed to this function from _process_ips through the Queue. New IPs are added to a list, which
    is then continuously looped over to check and see if the timeout threshold has been reached for locked out IPs.
    If reached, remove the iptable rule and reset that Ip_Node object to 0 _failed_logins """

    ip_failed_auth_list = []

    while True:
        try:
            ip_address = q.get(timeout=5)
            ip_failed_auth_list.append(ip_address)
            logger.info(f"_check_timeout found new IP in Queue {ip_address} |"
                        f"Added to ip_failed_list {ip_failed_auth_list}")

        except queue.Empty:
            logger.info(f"_check_timeout has an empty queue")

        for ip_node in ip_failed_auth_list:
            if isinstance(timeout, bool):
                logger.info(f"Timeout is not set. Default to indefinite IPTABLE rule")
                break

            if datetime.now() > (ip_node.time_added + timedelta(minutes=timeout) and ip_node.is_blocked):
                _lockout(ip_node.ip_address, True)
                ip_node.failed_logins = 0
                ip_node.is_blocked = False
                ip_failed_auth_list.remove(ip_node)
                logger.info(f"{timeout} minutes have passed since {ip_node}'s last failed Login."
                            f"Removing IPTABLE rule for {ip_node}. {ip_node} can now SSH")


def _build_parser():
    """ Build Parser to accept user-defined arguments """
    parser = argparse.ArgumentParser(description="SSH Failed Authentication Monitor")
    required_args = parser.add_argument_group('Required Arguments')
    required_args.add_argument('-l', '--lockout', required=True, type=int, help="Please enter a number for the "
                                                                                "threshold for "
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

    handlers = [file_handler_info, file_handler_warning, file_handler_error, stream_handler]
    formatter = logging.Formatter('%(asctime)s || %(levelname)s || %(message)s || %(name)s')

    for handler in handlers:
        logger.addHandler(handler)
        handler.setFormatter(formatter)

    return logger


if __name__ == '__main__':
    main()
