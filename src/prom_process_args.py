import argparse
import os
import sys


def add_args():
    examples = """examples:
    ./prom_trace.sh -p 123    # trace only process with PID 123
    ./prom_trace.sh -u 7      # update information every 7 seconds (3 by default)
    ./prom_trace.sh -ns       # do not trace syscalls
    """

    parser = argparse.ArgumentParser(description="Trace a process and export to grafana",
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=examples)
    parser.add_argument("-p", "--pid", help="trace this PID only", nargs="*")
    parser.add_argument("-c", "--comm", help="trace this COMM name only", nargs="*")
    parser.add_argument("-u", "--upd", help="set refresh time(in seconds)", nargs="?", const="3", default="3")

    parser.add_argument("-nt", "--ntcp", help="do not trace tcp events", nargs="?", const="t", default="n")
    parser.add_argument("-nr", "--nrw", help="do not trace read/write events", nargs="?", const="t", default="n")
    parser.add_argument("-ns", "--nsysc", help="do not trace number of syscalls", nargs="?", const="t", default="n")
    parser.add_argument("-nc", "--nrec", help="do not trace CPU and mem usage", nargs="?", const="t", default="n")

    return parser


def process_args():
    parser = add_args()
    args = parser.parse_args()

    # dict to return
    arguments = {}

    # required arguments not passed
    if not args.comm and not args.pid:
        print("Error: you must specify at least PID or COMM")
        sys.exit(1)

    # change refresh time
    if args.upd:
        try:
            upd_time = float(args.upd)
            if upd_time <= 0:
                print("Error: -u argument must a be positive number")
                sys.exit(1)
            else:
                arguments['upd'] = upd_time
        except ValueError:
            print("Error: -u argument must a be positive number")
            sys.exit(1)
    else:
        arguments['upd'] = 3.0

    # trace tcp events?
    if args.ntcp == 't':
        arguments['tcp'] = False
    elif args.ntcp == 'n':
        arguments['tcp'] = True
    else:
        print("Error: invalid --ntcp argument")
        sys.exit(1)

    # trace read/write events?
    if args.nrw == 't':
        arguments['rw'] = False
    elif args.nrw == 'n':
        arguments['rw'] = True
    else:
        print("Error: invalid --nrw argument")
        sys.exit(1)

    # count syscalls?
    if args.nsysc == 't':
        arguments['sys'] = False
    elif args.nsysc == 'n':
        arguments['sys'] = True
    else:
        print("Error: invalid --nsysc argument")
        sys.exit(1)

    # trace CPU and mem usage?
    if args.nrec == 't':
        arguments['rec'] = False
    elif args.nsysc == 'n':
        arguments['rec'] = True
    else:
        print("Error: invalid --nrec argument")
        sys.exit(1)

    if args.comm:
        arguments['args_comm'] = args.comm
    else:
        arguments['args_comm'] = []

    if args.pid:
        for p in args.pid:
            if not p.isdigit():
                print(f'Invalid --pid argument: \'{p}\', should be positive integer')
                sys.exit(1)
        arguments['args_pid'] = args.pid
    else:
        arguments['args_pid'] = []

    return arguments
