import os


# command line arguments
args_comm = []
args_pid = []
dump_path = ''
refresh_time = 2
# for opening dumpfile
fp = 0


# convert integer ip address to str with dots
def int_to_ip(addr):
    o1 = int(addr / (256 ** 3)) % 256
    o2 = int(addr / (256 ** 2)) % 256
    o3 = int(addr / 256) % 256
    o4 = int(addr) % 256

    return f'{o4}.{o3}.{o2}.{o1}'


# get list of pids with COMM name
def get_pids_by_comm(comm):
    pids_str = os.popen(f"pidof {comm}").read().rstrip()
    if len(pids_str) == 0:
        return []

    pids_list = [int(i) for i in pids_str.split(' ')]
    return pids_list


def get_traced_pids():
    new_traced_pids = []
    for comm in args_comm:
        new_traced_pids.extend(get_pids_by_comm(comm))
    for p in utils.args_pid:
        new_traced_pids.append(p)
    return new_traced_pids
    
    
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
