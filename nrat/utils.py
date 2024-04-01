import argparse
import logging
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
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument('--quick', action='store_true', default=False,
                               help='Perform a ping sweep and ARP request, printing live hosts')
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument('-i', '--icmp-ping', action='store_true', default=False, help='Perform ICMP ping scan')
    scan_group.add_argument('-A', '--arp-scan', action='store_true', default=False,
                            help='Perform ARP scan on target network')
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', default=None, help='Save output to a file')
    parser.add_argument('-t', '--threads', type=int, default=40, help='Number of threads for parallel execution')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Enable verbose logging')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='Enable debug logging')

    return parser.parse_args()

def execute_tasks(tasks, max_workers):
    # Execute given tasks in parallel using ThreadPoolExecutor
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(task_func, arg) for task_func, arg in tasks]
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.extend(result)
            except Exception as e:
                logging.warning(f'Task execution error: {e}')
    return results

def configure_logging(args):
    # Configure logging based on command line arguments
    if args.debug:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)
    conf.verb = 2 if args.verbose else 0
