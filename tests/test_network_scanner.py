import unittest
from network_scanner import NetworkScanner

class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NetworkScanner(target='192.168.1.0/24')

    def test_validate_target_valid(self):
        # Test validating a valid target network
        try:
            self.scanner.validate_target()
        except ValueError:
            self.fail("validate_target() raised ValueError unexpectedly!")

    def test_validate_target_invalid(self):
        # Test validating an invalid target network
        with self.assertRaises(ValueError):
            invalid_scanner = NetworkScanner(target='192.168.1.999')
            invalid_scanner.validate_target()

    def test_icmp_sweep(self):
        # Test running an ICMP sweep
        # This test may need to be adjusted to avoid actual network calls in unit tests
        results = self.scanner.icmp_sweep()
        self.assertIsInstance(results, list)

    # Additional tests for other methods can be added here

if __name__ == '__main__':
    unittest.main()
