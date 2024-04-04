import ipaddress
import logging
from .utils import setup_argparse as args
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sr, sr1
from scapy.layers.inet import IP, ICMP, TCP
from concurrent.futures import ThreadPoolExecutor

# Setup structured logging
def setup_logger():
    logger = logging.getLogger(__name__)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

logger = setup_logger()

class NetworkScanner:
    def __init__(self, target: str, timeout=1):
        self.target = target
        self.timeout = timeout
        self.validate_target()

    def validate_target(self):
        try:
            ipaddress.ip_network(self.target, strict=False)
            logger.info("Validated target network: %s", self.target)
        except ValueError as e:
            logger.error("Invalid network target: %s - %s", self.target, e)
            raise

    def arp_sweep(self):
        """
        Scans the specified network range using ARP requests to identify active hosts.
        """
        # Start logging 
        logger.info("ARP sweep started on %s", self.target)
        # Create ARP packet
        arp = ARP(pdst=self.target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        # Send packet and receive response 
        answerd, unanswered = srp(packet, 
                                  timeout=self.timeout, 
                                  verbose=args.verbose
                                  )[0]
        hosts = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in results]
        return hosts

    def ack_scan(self):
        """
        Perform an ACK scan on the target network.
        """
        logger.info("ACK scan started on %s", self.target)
        packet = IP(dst=self.target) / TCP(dport=args.ports, flags="A")
        ans, unans = sr(packet, timeout=self.timeout, verbose=0)
        # Further processing of `ans` and `unans` can be done here

    def icmp_sweep(self):
        """
        Perform an ICMP sweep on the target network.
        """
        logger.info("ICMP sweep started on %s", self.target)
        network = ipaddress.ip_network(self.target, strict=False)
        with ThreadPoolExecutor() as executor:
            tasks = [executor.submit(self.ping_host, str(host)) for host in network.hosts()]
            results = [task.result() for task in tasks]
        return results

    def ping_host(self, host):
        """
        Ping a single host using ICMP.

        :param host: IP address of the host to ping.
        """
        packet = IP(dst=host) / ICMP()
        try:
            response = sr1(packet, timeout=self.timeout, verbose=False)
            if response:
                logger.debug("Host %s is up (IP: %s, TTL: %s)", host, response.src, response.ttl)
                return {"host": host, "status": "up", "ip": response.src, "ttl": response.ttl}
            else:
                logger.debug("Host %s did not respond", host)
                return {"host": host, "status": "down"}
        except Exception as e:
            logger.error("Error pinging %s: %s", host, e)


