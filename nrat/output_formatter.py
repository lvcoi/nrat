import json
import logging
from itertools import zip_longest

logger = logging.getLogger(__name__)

class OutputFormatter:
    @staticmethod
    def print_in_columns(*methods_results):
        # Print results in columns for better readability
        for row in zip_longest(*methods_results, fillvalue=''):
            print('    '.join(f"{ip}".ljust(20) for ip in row))

    def print_and_store_results(self, results, output_file=None):
        # Print results to the console and store them in a file if specified
        if not results:
            return

        print(json.dumps(results, indent=4))

        if output_file:
            try:
                with open(output_file, 'w') as file:
                    json.dump(results, file, indent=4)
                logger.info(f'Results saved to {output_file} in JSON format.')
            except IOError as e:
                logger.error(f'Error saving results to {output_file}: {e}')
