import socket

from data_scraping import startup
from data_scraping import utils
from data_scraping import metrics


def do_tracing(args):
	
	# process command line arguments
	startup.process_args(args)
	
	# prepare eBPF program to load to kernel
	bpf_program = startup.get_bpf_program()
	bpf_program = startup.substitute_macros(bpf_program, args['args_pid'])
	
	# load BPF program to kernel
	b = startup.load_bpf_program(bpf_program)
	
	# initialize prometheus metrics
	metrics.initialize_metrics(b)
	
	# start local server to store metrics
	startup.start_metrics_server(5000)
	
	print("Tracing started successfully (Ctrl + C to exit)")
	
	try:
		while True:
			# poll eBPF events for refresh_time seconds, then update other metrics
			metrics.update_values(utils.refresh_time, b)
			
	except KeyboardInterrupt:
		raise
