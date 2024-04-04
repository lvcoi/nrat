import argparse
import json
import sys
import logging

logger = logging.getLogger(__name__)
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.config import conf

def setup_argparse():
    # Set up and return the argument parser
    parser = argparse.ArgumentParser(description="Network Reconnaissance Tool")
    parser.usage = """ nrat.py [options] target

        Network Reconnaissance and Analysis Tool (NRAT)

        Perform various network scans on the specified target.

        Target:
          The target can be an IP address, hostname, or CIDR range.

        Examples:
        nrat.py --quick 192.168.0.0/24
          Perform a quick ping sweep and ARP scan on the 192.168.0.0/24 network.

        nrat.py -i -A -t 40 -o scan_results.json 10.0.0.0/16
          Perform ICMP ping scan and ARP scan on the 10.0.0.0/16 network using 40 threads
          and save the results in JSON format to scan_results.json.
    """

    parser.add_argument('target', help='Target IP address, hostname, or CIDR range')
    parser.add_argument('--timeout', type=int, default=1, help='Timeout for network requests in seconds')
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument('--quick', action='store_true', default=False,
                               help='Perform a ping sweep and ARP request, printing live hosts')
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument('-i', '--icmp-ping', action='store_true', default=False, help='Perform ICMP ping scan')
    scan_group.add_argument('-A', '--arp-scan', action='store_true', default=False,
                            help='Perform ARP scan on target network')
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', default=None, help='Save output to a file')
    parser.add_argument('-p', '--ports', type=list, default=[80,443,22,21,25], help='Ports to scan')
    parser.add_argument('-t', '--threads', type=int, default=40, help='Number of threads for parallel execution')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Enable verbose logging')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='Enable debug logging')

    return parser.parse_args()

def execute_tasks(tasks, max_workers):
    """
    Execute a list of tasks in parallel using a thread pool.
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(task[0], *task[1:]): task for task in tasks if isinstance(task, tuple)}
        
        for future in as_completed(futures):
            task = futures[future]
            try:
                result = future.result()
                results.append(result)
                logger.debug(f"Task completed: {task[0].__name__}")
            except Exception as e:
                logger.error(f'Task execution error in {task[0].__name__}: {e}', exc_info=True)

    return results

def configure_logging(args):
    """
    Configure structured logging for the application.
    """
    log_level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING

    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logging.getLogger().addHandler(handler)

    if args.debug:
        conf.verb = 2
    else:
        conf.verb = 0

if __name__ == '__main__':
    args = setup_argparse()
    configure_logging(args)