import json
import logging
from itertools import zip_longest

logger = logging.getLogger(__name__)

class OutputFormatter:
    @staticmethod
    def print_in_columns(*methods_results):
        for row in zip_longest(*methods_results, fillvalue=''):
            print('    '.join(f"{ip}".ljust(20) for ip in row))

    def print_and_store_results(self, results, output_file=None):
        if not results:
            return

        print(json.dumps(results, indent=4))

        if output_file:
            try:
                with open(output_file, 'w') as file:
                    json.dump(results, file, indent=4)
                logger.info(json.dumps({"message": "Results saved", "output_file": output_file, "status": "success"}))
            except IOError as e:
                logger.error(json.dumps({"message": "Error saving results", "output_file": output_file, "error": str(e)}))
