import os
import sys
import subprocess
import requests

# command line arguments
args_comm = []
args_pid = []
refresh_time = 2
trace_tcp = True
trace_rw = True
trace_sc = True
trace_rec = True


# convert integer ip address to str with dots
def int_to_ip(addr):
    o1 = int(addr / (256 ** 3)) % 256
    o2 = int(addr / (256 ** 2)) % 256
    o3 = int(addr / 256) % 256
    o4 = int(addr) % 256

    return f'{o4}.{o3}.{o2}.{o1}'


def get_prometheus_server_ip():
    return docker_.get_prometheus_server_ip()


# get list of pids with COMM name
def get_pids_by_comm(comm):
    pids_str = os.popen(f"pidof {comm}").read().rstrip()
    if len(pids_str) == 0:
        return []

    pids_list = [int(i) for i in pids_str.split(' ')]
    return pids_list


# measures CPU usage (in seconds) during the latest seconds
def pid_total_cpu_time(pid):
    try:
        stats = open(f"/proc/{pid}/stat", "r").read().rstrip().split(" ")
        utime = int(stats[13])
        stime = int(stats[14])
        cutime = int(stats[15])
        cstime = int(stats[16])

        total_time_ticks = utime + stime
        ticks_in_seconds = int(os.popen("getconf CLK_TCK").read())

        return total_time_ticks / ticks_in_seconds

    except (FileNotFoundError, IOError, IndexError):
        return 0


# measures CPU usage (in percents) during the whole life of process
def pid_whole_cpu_usage(pid):
    try:
        stats = open(f"/proc/{pid}/stat", "r").read().rstrip().split(" ")
        utime = int(stats[13])
        stime = int(stats[14])
        cutime = int(stats[15])
        cstime = int(stats[16])
        total_time_ticks = utime + stime

        ticks_in_seconds = int(os.popen("getconf CLK_TCK").read())
        total_seconds = total_time_ticks / ticks_in_seconds
        # how lomg time ago system started
        uptime = float(open(f"/proc/uptime", "r").read().rstrip().split(" ")[0])
        # how long time ago process started
        starttime = int(stats[21]) / ticks_in_seconds

        return 100 * total_seconds / (uptime - starttime)

    except (FileNotFoundError, IOError, IndexError):
        return 0


# get process cpu usage
def pid_memory_usage(pid):
    try:

        vmrss = int(open(f"/proc/{pid}/status", 'r').read().split('\n')[21].split(' ')[-2])

        return vmrss

    except (FileNotFoundError, IOError, IndexError):
        return 0


# get country code by IP
def get_country_code(ip):
    response = requests.get(f'http://ipinfo.io/{ip}')
    lines = response.content.decode().split('\n')
    line = [i for i in lines if 'country' in i]
    try:
        return line[0].split(':')[1].split('\"')[1]

    except IndexError:
        return ''


FILTER_PID_macro = '                                                                    \
            u32 filter_pid = bpf_get_current_pid_tgid() >> 32;                          \
            int pids[NUMBER_OF_PIDS] = { LIST_OF_PIDS } ;                               \
            bool filtered = false;                                                      \
            for( int i = 0; i< NUMBER_OF_PIDS; i++)                                	\
            {                                                                           \
                if (filter_pid == pids[i])                                              \
                {                                                                       \
                    filtered = true;                                                    \
                    break;                                                              \
                }                                                                       \
            }                                                                           \
            if (!filtered)                                                              \
            {                                                                           \
                return 0;                                                               \
            }                                                                           \
'
# not used in current version
FILTER_COMM_macro = '                                                                   \
            char filter_comm[TASK_COMM_LEN];                                            \
            bpf_get_current_comm(&filter_comm, sizeof(filter_comm));                    \
            char* filter_name_ptr = "FILTER_COMM";                                      \
                                                                                        \
            for(int i = 0; i<20; i++)                                                   \
            {                                                                           \
                if(*(filter_name_ptr + i) != filter_comm[i])                            \
                {                                                                       \
                    return 0;                                                           \
                }                                                                       \
                                                                                        \
                if(*(filter_name_ptr + i) == \'\\0\' && filter_comm[i] == \'\\0\')      \
                {                                                                       \
                    break;                                                              \
                }                                                                       \
            }                                                                           \
'
