import logging
from utils import setup_argparse, configure_logging, execute_tasks
from network_scanner import NetworkScanner
from output_formatter import OutputFormatter

def main():
    # Parse command line arguments and configure logging
    args = setup_argparse()
    configure_logging(args)

    # Initialize the network scanner and validate the target
    scanner = NetworkScanner(args.target)
    scanner.validate_target()

    # Initialize the output formatter
    formatter = OutputFormatter()

    # Prepare and execute scanning tasks based on user input
    tasks = []
    if args.quick or args.icmp_ping:
        tasks.append((scanner.icmp_sweep, None))
    if args.quick or args.arp_scan:
        tasks.append((scanner.arp_scan, None))

    scan_results = execute_tasks(tasks, args.threads)

    # Output the scan results
    results = {'scan_results': scan_results}
    formatter.print_and_store_results(results, args.output)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info('Scan interrupted by user.')
    except Exception as e:
        logging.critical(f'Unhandled exception: {e}', exc_info=True)
