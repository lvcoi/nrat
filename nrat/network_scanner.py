import ipaddress
import logging
from scapy.all import ICMP, IP, sr1, ARP, Ether, srp

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, target: str, timeout=1):
        # Initialize the NetworkScanner with a target and timeout
        self.target = target
        self.timeout = timeout

    def validate_target(self):
        # Validate the target IP address or CIDR range
        try:
            ipaddress.ip_network(self.target, strict=False)
            logger.info(f"Target {self.target} is a valid IP network.")
        except ValueError as e:
            logger.error(f"Invalid network target: {self.target} - {e}")
            raise

    def icmp_sweep(self):
        # Perform an ICMP sweep (ping) on the target network
        method = "ICMP Sweep"
        logger.info(f"{method} started on {self.target}")
        results = []
        network = ipaddress.ip_network(self.target, strict=False)
        for host in network.hosts():
            result = self.ping_host(str(host))
            if result:
                results.append(result)
        return results

    def ping_host(self, host):
        # Send an ICMP ping request to a single host
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
        except OSError as e:
            logger.warning(f"{method} - Error pinging {host}: {e}")

    def arp_scan(self):
        # Perform an ARP scan on the target network
        method = "ARP Scan"
        logger.info(f"{method} started on {self.target}")
        results = []
        network = ipaddress.ip_network(self.target, strict=False)
        for host in network.hosts():
            arp_request = ARP(pdst=str(host))
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered, _ = srp(broadcast / arp_request, timeout=self.timeout, verbose=0)
            for _, received in answered:
                logger.debug(f"{method} - Host {received.psrc} is up (MAC: {received.hwsrc})")
                results.append({"host": received.psrc, "mac": received.hwsrc})
        return results
