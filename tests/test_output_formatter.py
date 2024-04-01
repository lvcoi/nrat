import unittest
from output_formatter import OutputFormatter

class TestOutputFormatter(unittest.TestCase):
    def setUp(self):
        self.formatter = OutputFormatter()

    def test_print_in_columns(self):
        # Test printing in columns, this test mostly checks if the method runs without error
        # Actual printing to the console is hard to capture in unit tests
        try:
            self.formatter.print_in_columns(['192.168.1.1', '192.168.1.2'], ['192.168.1.3'])
        except Exception as e:
            self.fail(f"print_in_columns() raised an exception {e}")

    def test_print_and_store_results(self):
        # Test print and store functionality, ideally should mock file operations
        results = {'host': '192.168.1.1', 'status': 'up'}
        try:
            self.formatter.print_and_store_results(results)
        except Exception as e:
            self.fail(f"print_and_store_results() raised an exception {e}")

    # Additional tests for other methods and error handling can be added here

if __name__ == '__main__':
    unittest.main()
