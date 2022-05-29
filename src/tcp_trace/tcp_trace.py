import sys
import time
import datetime
from bcc import BPF
import argparse
import os

import utils

def update_values(seconds, bpf):
    global traced_pids

    start = time.time()

    # update metrics connected with eBPF events
    while time.time() - start < seconds:
        bpf.perf_buffer_poll(timeout=int(seconds*1000))
    
    # if we have dynamically changing PIDs that we need to trace
    if len(utils.args_comm) > 0:
        traced_pids = utils.get_traced_pids()


# processes perf_buffer polling
def update_tcp_events(cpu, data, size):
    event = b["ipv4_events"].event(data)
    # check if this COMM is traced
    if (not (int(event.pid) in traced_pids)) and len(utils.args_comm) > 0:
        return
   
    ip_addr = utils.int_to_ip(int(event.daddr))

    global start_ts_ms
    # initialize start time
    if start_ts_ms == 0:
	    start_ts_ms = event.ts_ms
	    
    conn_time = start_trace_time + datetime.timedelta(milliseconds = event.ts_ms - start_ts_ms)
    conn_time_str = conn_time.strftime('%H:%M:%S.%f')[:-3]
	    
    type_char = 'U'
    if event.type == 0:
        type_char = 'C'
    elif event.type == 1:
        type_char = 'X'
	    
    dump_str_line = f'{conn_time_str}   {type_char}   {event.pid}   {utils.int_to_ip(int(event.saddr))}:{event.sport} > {utils.int_to_ip(int(event.daddr))}:{event.dport}'
    if utils.dump_path == '':
    	print(dump_str_line)
    else:
        try:
            utils.fp.write(dump_str_line+'\n')
        except OSError:
            print("Error: unable to write to dump file")
            sys.exit(1)
   	

if __name__ == '__main__':
	# declare some global variables
	global traced_pids
	global b
	global start_trace_time
	global start_ts_ms
	
	traced_pids = []
	# eBPF object
	b = {}
	# start time
	start_trace_time = datetime.datetime.now()
	start_ts_ms = 0
	
	# process command line arguments
	parser = argparse.ArgumentParser(description="Dump tcp connection info")
	parser.add_argument("-p", "--pid", help="trace this PID only", nargs="*")
	parser.add_argument("-c", "--comm", help="trace this COMM name only", nargs="*")
	parser.add_argument("-u", "--upd", help="set refresh time(in seconds)", nargs="?", const="3", default="3")
	parser.add_argument("-d", "--dump", help="dump tcp connection information to file or standart output", nargs="?",
                        const="std", default="n")
	args = parser.parse_args()
	
	# change refresh time
	if args.upd != "3":
		utils.refresh_time = float(args.upd)
 
	# find place to dump tcp info
	if args.dump == "std":
		# dump to standard output
		utils.dump_path = ""
	elif args.dump != "n":
		if args.dump[0] == '/':
			utils.dump_path = args.dump
		else:
			utils.dump_path = '/'.join(__file__.split('/')[:-3]) + "/" + args.dump
		utils.dump_path = os.path.realpath(utils.dump_path)
		
		if not os.path.isdir(os.path.dirname(utils.dump_path)):
			# check if file exists or at least can be created in given directory
			print(f'Error: invalid path, file {args.dump} cannot be opened or created')
			sys.exit(1)
	if args.comm:
		utils.args_comm = args.comm
	if args.pid:
		utils.args_pid = args.pid
		for p in utils.args_pid:
			if not p.isdigit():
				print(f'Invalid --pid argument: \'{p}\', should be positive integer')
				sys.exit(1)
	
	# prepare eBPF program to load to kernel
	with open('/'.join(__file__.split('/')[:-1]) + "/BPFprogram.c") as f:
        	bpf_program = f.read()
	# make macro replacement
	if len(utils.args_pid) > 0:
		number_of_pids_str = str(len(utils.args_pid))
		all_pids_str = ""
		for pid in utils.args_pid:
			all_pids_str += str(pid) + ","
		all_pids_str = all_pids_str[:-1]
		bpf_program = bpf_program.replace("FILTER_PID", utils.FILTER_PID_macro
                                    .replace("NUMBER_OF_PIDS", number_of_pids_str)
                                    .replace("LIST_OF_PIDS", all_pids_str))
	else:
        	bpf_program = bpf_program.replace("FILTER_PID", "")

	# load BPF program to kernel
	b = BPF(text=bpf_program)
	b.attach_kretprobe(event="tcp_v4_connect", fn_name="tcp_v4_connect_ret")
	b.attach_kprobe(event="tcp_v4_connect", fn_name="tcp_v4_connect_entry")
	b.attach_kprobe(event="tcp_close", fn_name="trace_close_entry")
    

	# get access to perf_buffer with all kernel events
	b["ipv4_events"].open_perf_buffer(update_tcp_events, page_cnt=16)

	if utils.dump_path != '':
		try:
			utils.fp = open(utils.dump_path, 'a')
		except OSError:
			print("Error: unable to open or create dump file")
			exit(1)

	print("Tracing started successfully ( Ctrl + C to exit )")
	
	try:
		while True:
			# poll eBPF events for refresh_time seconds, then update other metrics
			update_values(utils.refresh_time, b)
			
	except KeyboardInterrupt:
		exit(0)
