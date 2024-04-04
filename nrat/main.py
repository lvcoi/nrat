import logging
from .utils import setup_argparse, configure_logging
from .network_scanner import NetworkScanner
from .output_formatter import OutputFormatter
import json

import logging
import os
from .utils import setup_argparse, configure_logging
from .network_scanner import NetworkScanner

def configure_logging(args):
    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.ERROR

    # Configure the logging with the log_level
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Additional logging configuration as needed

    log_dir = "/tmp/nrat/"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "nrat.log")

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    # Clear existing handlers, if any
    if logger.handlers:
        logger.handlers = []

    logger.addHandler(file_handler)


def main():
    args = setup_argparse()
    configure_logging()

    if args.arp_scan:
        scanner = NetworkScanner(args.target)
        scanner.arp_scan()
    # Handle other scan types based on the arguments

if __name__ == '__main__':
    main()
        
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info('Scan interrupted by user.')
    except Exception as e:
        logging.critical('Unhandled exception occurred.', exc_info=True)
