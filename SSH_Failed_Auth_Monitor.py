import argparse
import logging
import os
import pathlib
import subprocess
import re
import sys

from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from logging.handlers import RotatingFileHandler
from threading import Lock
from time import sleep


# TODO: Log files are going to the right place on Windows? Mac? Can we test that?

def _delay_wrapper(val):
    def inner(func):
        @wraps(func)
        def decorator(*args, **kwargs):
            sleep(val)
            return func(*args, **kwargs)

        return decorator

    return inner


def main():
    """ Main function. Builds the Parser for arguments, Logging, and starts Threads """
    # args = _build_parser()
    # logger = _build_logger()
    _read_log()
    # with ThreadPoolExecutor(max_workers=2) as executor:
    #     executor.submit(_read_log)
    #     executor.submit(_monitor_auth, args.lockout, args.timeout)


def _read_log():
    regex_ip = re.compile(r'(^([12])?((?<=2)[0-5]|(?<!2)[0-9])?((?<=25)[0-5]|(?<!25)[0-9])?$)')
    with open('/var/log/auth.log', 'r') as file:
        file.seek(0, os.SEEK_END)
        while True:
            line = file.readline()
            if not line:
                sleep(1)
                continue
            yield line

        # subprocess.call(f'echo {file} | ')


def _monitor_auth(threshold, timeout):
    pass


def _build_parser():
    """ Build Parser to accept user-defined arguments """
    parser = argparse.ArgumentParser(description="SSH Failed Authentication Monitor")
    parser.add_argument('-l', '--lockout', required=True, type=int, help="Please enter a number for the threshold for "
                                                                         "failed login attempts")
    parser.add_argument('-t', '--timeout', required=False, type=int, default=True,
                        help="Specify the length of time (minutes) the user will "
                             "be locked out if threshold is met (Optional)")
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
