from bcc import BPF
import prometheus_client as prom
import argparse
import os
import sys

from data_scraping import utils


def process_args(args):
    
    # change refresh time
    utils.refresh_time = args['upd']

    utils.args_comm = args['args_comm']
    utils.args_pid = args['args_pid']
    
    utils.trace_tcp = args['tcp']
    utils.trace_rw = args['rw']
    utils.trace_sc = args['sys']
    utils.trace_rec = args['rec']
        

def get_bpf_program():
    with open('/'.join(__file__.split('/')[:-1]) + "/BPFprogram.c") as f:
        return f.read()


def substitute_macros(bpf_prog, arg_pid_list):
    if not utils.trace_sc:
        # just delete unnecessary code
        splitted_prog = bpf_prog.split("//split//") 
        splitted_prog.pop(1)
        bpf_prog = ''.join(splitted_prog)
    if arg_pid_list:
        number_of_pids_str = str(len(arg_pid_list))
        list_of_pids_str = ""
        for pid in arg_pid_list:
            list_of_pids_str += str(pid) + ","
        list_of_pids_str = list_of_pids_str[:-1]

        bpf_prog = bpf_prog.replace("FILTER_PID", utils.FILTER_PID_macro
                                    .replace("NUMBER_OF_PIDS", number_of_pids_str)
                                    .replace("LIST_OF_PIDS", list_of_pids_str))
    else:
        bpf_prog = bpf_prog.replace("FILTER_PID", "")

    return bpf_prog


def load_bpf_program(bpf_prog):
    b = BPF(text=bpf_prog)
    if utils.trace_tcp:
        b.attach_kretprobe(event="tcp_v4_connect", fn_name="tcp_v4_connect_ret")
        b.attach_kprobe(event="tcp_v4_connect", fn_name="tcp_v4_connect_entry")
        b.attach_kprobe(event="tcp_sendmsg", fn_name="get_sent")
        b.attach_kprobe(event="tcp_recvmsg", fn_name="get_received")
    if utils.trace_rw:
        b.attach_kprobe(event="vfs_read", fn_name="read_entry")
        b.attach_kprobe(event="vfs_write", fn_name="write_entry")

    return b


def start_metrics_server(port):
    prom.start_http_server(port)
