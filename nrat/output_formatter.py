import json
import logging
from itertools import zip_longest

logger = logging.getLogger(__name__)

class OutputFormatter:
    """
    OutputFormatter handles the formatting and output of scan results.
    """

    @staticmethod
    def print_in_columns(methods_results):
        """
        Print results in columns for better readability.

        :param methods_results: A list of results from different methods.
        """
        for row in zip_longest(*methods_results, fillvalue=''):
            print('    '.join(str(item).ljust(20) for item in row))

    def print_and_store_results(self, results, output_file=None):
        """
        Print results to the console and optionally store them in a file.

        :param results: Scan results to be printed and stored.
        :param output_file: File path to save the results. If None, results are only printed to the console.
        """
        if not results:
            logger.info("No results to display.")
            return

        results_str = json.dumps(results, indent=4)
        print(results_str)

        if output_file:
            try:
                with open(output_file, 'w') as file:
                    file.write(results_str)
                logger.info("Results saved to file.", extra={"output_file": output_file, "status": "success"})
            except IOError as e:
                logger.error("Error saving results to file.", extra={"output_file": output_file, "error": str(e)})

