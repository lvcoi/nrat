import ipaddress
import logging
import json
from scapy.layers.l2 import ARP, Ether, srp
from scapy.layers.dns import sr1
from scapy.layers.inet import IP, ICMP
from concurrent.futures import ThreadPoolExecutor

# Setup structured logging
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

class NetworkScanner:
    def __init__(self, target: str, timeout=1, quick_scan_mode=False):
        self.target = target
        self.timeout = timeout
        self.quick_scan_mode = quick_scan_mode
        self.validate_target()

    def validate_target(self):
        try:
            ipaddress.ip_network(self.target, strict=False)
            logger.info("Validated target network: %s", self.target)
        except ValueError as e:
            logger.error("Invalid network target: %s - %s", self.target, e)
            raise
    
    def icmp_sweep(self):
        """
        Perform an ICMP sweep on the target network.
        """
        method = "ICMP Sweep"
        logger.info(f"{method} started on {self.target}")
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
        method = "Ping Host"
        packet = IP(dst=host)/ICMP()
        try:
            response = sr1(packet, timeout=self.timeout, verbose=False)
            if response:
                logger.debug(f"{method} - Host {host} is up (IP: {response.src}, TTL: {response.ttl})")
                return {"host": host, "status": "up", "ip": response.src, "ttl": response.ttl}
            else:
                logger.debug(f"{method} - Host {host} did not respond")
                return {"host": host, "status": "down"}
        except ipaddress.AddressValueError as e:
            logger.error(f"{method} - Error pinging {host}: {e}")

    def arp_sweep(self):
       """
       Scans the specified network range and returns a list of responding hosts.
       Args:
           cidr (str): The network range to scan, in CIDR notation.
       Returns:
           list: A list of dictionaries, where each dictionary represents a responding
                 host and contains the keys 'ip' (IP address) and 'mac' (MAC address).
       """
       arp = ARP(pdst=self.target)
       ether = Ether(dst="ff:ff:ff:ff:ff:ff")
       packet = ether/arp
       result = srp(packet, timeout=3, verbose=0)[0]
       clients = []
       for sent, received in result:
           clients.append({'ip': received.psrc, 'mac': received.hwsrc})
       return clients                  
    
    def arp_request(self, arp_request):
        """
        Send an ARP request.

        :param arp_request: The ARP request packet to send.
        """
        method = "ARP Request"
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(broadcast / arp_request, timeout=self.timeout, verbose=False)
        results = [{"host": received.psrc, "mac": received.hwsrc} for _, received in answered]
        for result in results:
            logger.debug(f"{method} - Host {result['host']} is up (MAC: {result['mac']})")
        return results
