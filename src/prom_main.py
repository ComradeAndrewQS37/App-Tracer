from data_scraping import trace_main
import prom_process_args

import sys

if __name__ == '__main__':
    # get args dict
    args = prom_process_args.process_args()
    try:
        # start tracing and poll new events
        trace_main.do_tracing(args)
    except KeyboardInterrupt:
        sys.exit(0)
