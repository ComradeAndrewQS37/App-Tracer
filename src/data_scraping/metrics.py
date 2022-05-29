import prometheus_client as prom
import time
import datetime
from bcc.syscall import syscall_name, syscalls

from data_scraping import utils

# define prometheus metrics
tcp_cnt = prom.Counter('connections_established', 'How many TCP connections were established', ['ip'])
recv_cnt = prom.Counter('bytes_received', 'Size of received packages (in bytes)', ['ip'])
sent_cnt = prom.Counter('bytes_sent', 'Size of sent packages (in bytes)', ['ip'])
cpu_usage = prom.Gauge('cpu_usage', 'Percentage of app CPU usage in last seconds')
mem_usage = prom.Gauge('memory_usage', 'Size of active used memory (VmRSS) in kilobytes')
total_mem = prom.Gauge('total_memory', 'Total size of memory available on the device in kilobytes')
syscalls_cnt = prom.Counter('syscalls', 'Amount of all syscalls made by process', ['func_name'])
geoip_cnt = prom.Counter('geoip', 'IPs with their countries', ['country'])
read_cnt = prom.Counter('read', 'Amount of all file reads', ['file_name'])
read_bytes_cnt = prom.Counter('read_bytes', 'Amount of bytes read', ['file_name'])
write_cnt = prom.Counter('write', 'Amount of all file writes', ['file_name'])
write_bytes_cnt = prom.Counter('write_bytes', 'Amount of bytes written', ['file_name'])

# list with pids traced 
traced_pids = []
# total CPU time of all traced processes
traced_cpu_time_total = 0
# latest point when cpu usage was updated
last_cpu_upd_time = 0
# eBPF object
b = {}
# start time
start_trace_time = datetime.datetime.now()
start_ts_ms = 0


def initialize_metrics(bpf):
    # initialize some values
    global traced_pids
    traced_pids = get_traced_pids()
    global traced_cpu_time_total
    global last_cpu_upd_time
    if utils.trace_rec:
        traced_cpu_time_total = sum([utils.pid_total_cpu_time(i) for i in traced_pids])
        last_cpu_upd_time = time.time()

    total_system_memory = int(open("/proc/meminfo", 'r').read().split('\n')[0].split(' ')[-2])
    total_mem.set(total_system_memory)

    # get access to perf_buffer with all kernel events
    bpf["package_events"].open_perf_buffer(update_package_events, page_cnt=32)
    bpf["ipv4_events"].open_perf_buffer(update_tcp_events, page_cnt=32)

    global b
    b = bpf


def update_values(seconds, bpf):
    global traced_pids
    global last_cpu_upd_time
    start = time.time()

    # update metrics connected with eBPF events
    while time.time() - start < seconds:
        bpf.perf_buffer_poll(timeout=int(seconds * 1000))

    if utils.trace_rec:
        update_cpu_usage()
        update_mem_usage()

    global b
    syscall_data = b["syscalls"]
    for k, v in syscall_data.items():
        if (not (int(k.pid) in traced_pids)) and len(utils.args_comm) > 0:
            continue
        syscalls_cnt.labels(syscall_name(k.fn_id).decode()).inc(v.value)
    syscall_data.clear()

    io_data = b["io_counts"]
    for k, v in io_data.items():
        if (not (int(k.pid) in traced_pids)) and len(utils.args_comm) > 0:
            continue
        file_name = k.name.decode('utf-8', 'replace')
        if k.name_len > 32:
            file_name = file_name[:-3] + "..."
        read_cnt.labels(file_name).inc(int(v.reads))
        read_bytes_cnt.labels(file_name).inc(int(v.rbytes))
        write_cnt.labels(file_name).inc(int(v.writes))
        write_bytes_cnt.labels(file_name).inc(int(v.wbytes))
    io_data.clear()

    # if we have dynamically changing PIDs that we need to trace
    if len(utils.args_comm) > 0:
        traced_pids = get_traced_pids()


def update_cpu_usage():
    global traced_cpu_time_total
    global traced_pids
    global last_cpu_upd_time

    # if only PIDs are set, we can measure the CPU usage during the latest seconds
    # if we have COMM, new processes can be spawned or old ones can be finished, so
    # recent CPU usage cannot be measured correctly, total CPU usage after process start is measured
    if len(utils.args_comm) > 0:
        usage_val = sum([utils.pid_whole_cpu_usage(i) for i in traced_pids])
        cpu_usage.set(usage_val)

    else:
        current_cpu_upd_time = time.time()
        current_cpu_time = sum([utils.pid_total_cpu_time(i) for i in traced_pids])

        if (current_cpu_time - traced_cpu_time_total) <= 0:
            # check not to irritate the interpreter
            if cpu_usage:
                cpu_usage.set(0)
        else:
            usage_val = round(
                100 * (current_cpu_time - traced_cpu_time_total) / (current_cpu_upd_time - last_cpu_upd_time), 1)
            cpu_usage.set(usage_val)

        traced_cpu_time_total = current_cpu_time
        last_cpu_upd_time = current_cpu_upd_time


def update_mem_usage():
    total_memory_use = sum([utils.pid_memory_usage(i) for i in traced_pids])
    mem_usage.set(total_memory_use)


def get_traced_pids():
    new_traced_pids = []
    for comm in utils.args_comm:
        new_traced_pids.extend(utils.get_pids_by_comm(comm))
    for p in utils.args_pid:
        new_traced_pids.append(p)
    return new_traced_pids


# processes perf_buffer polling
def update_package_events(cpu, data, size):
    event = b["package_events"].event(data)
    if len(utils.args_comm) > 0:
        # PID wasn't filtered by eBPF
        if not (int(event.pid) in traced_pids):
            return
    if event.is_rcv == 1:
        ip_addr = utils.int_to_ip(int(event.daddr))
        recv_cnt.labels(ip_addr).inc(int(event.size))
    else:
        ip_addr = utils.int_to_ip(int(event.daddr))
        sent_cnt.labels(ip_addr).inc(int(event.size))


# processes perf_buffer polling
def update_tcp_events(cpu, data, size):
    event = b["ipv4_events"].event(data)
    if len(utils.args_comm) > 0:
        # PID wasn't filtered by eBPF
        if not (int(event.pid) in traced_pids):
            return

    ip_addr = utils.int_to_ip(int(event.daddr))
    tcp_cnt.labels(ip_addr).inc()
    country_code = utils.get_country_code(ip_addr)
    if country_code != '':
        geoip_cnt.labels(country_code).inc()
