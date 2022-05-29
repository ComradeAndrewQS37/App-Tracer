#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>


// for tracing sent and received
struct package_event
{
	int is_rcv;
	u32 pid;
	u32 daddr;
	u32 size;
};
BPF_PERF_OUTPUT(package_events);

enum conn_type
{
	CONNECT,
	CLOSE
};

struct ipv4_data_t {
    enum conn_type type;
    u64 ts_ms;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    
};
BPF_PERF_OUTPUT(ipv4_events);

//sockets in use
BPF_HASH(currsock, u64, struct sock *);


// for tracing syscalls
struct syscall_data
{
	u32 fn_id;
	u32 pid;
};
BPF_HASH(syscalls, struct syscall_data, u64);

// the key for storing the I/O info
struct io_info_key_t {
    u32 pid;
    u32 name_len;
    
    // de->d_name.name may point to de->d_iname so limit len accordingly
    char name[DNAME_INLINE_LEN];
    char type;
};


// the value for storing the I/O info
struct io_info_value_t {
    u64 reads;
    u64 writes;
    u64 rbytes;
    u64 wbytes;
};
BPF_HASH(io_counts, struct io_info_key_t, struct io_info_value_t);

//split//
// tracing syscalls
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    
    FILTER_PID
	
    u32 key = args->id;
    // skip invalid function id case
    if (key == -1) {
    	return 0;
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct syscall_data sd = {};
    sd.fn_id = key;
    sd.pid = pid;

    u64 *val;
    u64 zero = 0;
    val = syscalls.lookup_or_try_init(&sd, &zero);
    if (val) {
        ++(*val);
    }

    return 0;
}
//split//


// when new tcpv4 connection is established
int tcp_v4_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
	FILTER_PID
	
	//start tracing this socket
	u64 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &sk);
	
	return 0;
};


// when package exchange through tcpv4 connection is finished
int tcp_v4_connect_ret(struct pt_regs *ctx)
{

	//check if connection was successful
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **sockpp;
	sockpp = currsock.lookup(&pid);
	if (sockpp == 0) 
	{
		return 0;
	}
	if (ret != 0) 
	{
		currsock.delete(&pid);
		return 0;
	}
	
	// can end tracing this socket
	currsock.delete(&pid);
	
	// get info about this connection
	struct sock *sockp = *sockpp;
	u32 daddr = sockp->__sk_common.skc_daddr;
	u32 saddr = sockp->__sk_common.skc_rcv_saddr;
	if(saddr==0 || daddr == 0)
	{
		return 0;
	}
	struct inet_sock *i_skp = (struct inet_sock *)sockp;
  	u16 sport = i_skp->inet_sport;
  	u16 dport = sockp->__sk_common.skc_dport;
  	
	// save this info
	struct ipv4_data_t new_event = {};
	
	new_event.type = CONNECT;
	new_event.ts_ms = bpf_ktime_get_ns() / 1000000;
	new_event.pid = bpf_get_current_pid_tgid() >> 32;
	new_event.daddr = daddr;
	new_event.saddr = saddr;
	new_event.dport = ntohs(dport);
	new_event.sport = ntohs(sport);
	
	ipv4_events.perf_submit(ctx, &new_event, sizeof(new_event));
	
	
	return 0;
}


// when new package is sent via tcp connection
int get_sent(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
	FILTER_PID
	
	// save info about sent package
	struct package_event new_event = {};
	new_event.is_rcv = 0;
	new_event.pid = bpf_get_current_pid_tgid() >> 32;
	new_event.daddr = sk->__sk_common.skc_daddr;
	new_event.size = size;
	
	package_events.perf_submit(ctx, &new_event, sizeof(new_event));
	
	
	return 0;
}

// when new package is received via tcp connection
int get_received(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
	FILTER_PID
	
	// save info about received package
	struct package_event new_event = {};
	new_event.is_rcv = 1;
	new_event.pid = bpf_get_current_pid_tgid() >> 32;
	new_event.daddr = sk->__sk_common.skc_daddr;
	new_event.size = len;
	
	package_events.perf_submit(ctx, &new_event, sizeof(new_event));
		
	
    	return 0;
}

// process read/write events
static int process_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count, int is_read)
{

    FILTER_PID 
    
    // skip I/O lacking a filename
    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;
    if (d_name.len == 0)
        return 0;
        
    // skip if not a regular file
    int mode = file->f_inode->i_mode;
    if (!S_ISREG(mode)) 
    {
        return 0;
    } 
        
    // store counts and sizes by pid & file
    u32 pid = bpf_get_current_pid_tgid();
    struct io_info_key_t info = {};
    info.pid = pid;
    
    info.name_len = d_name.len;
    bpf_probe_read_kernel(&info.name, sizeof(info.name), d_name.name);
    
   
    // save info
    struct io_info_value_t *valp, zero = {};
    valp = io_counts.lookup_or_try_init(&info, &zero);
    if (valp) {
        if (is_read) {
            valp->reads++;
            valp->rbytes += count;
        } else {
            valp->writes++;
            valp->wbytes += count;
        }
    }
    return 0;
}

// when read function is called
int read_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count)
{
    return process_entry(ctx, file, buf, count, 1);
}

// when write function is called
int write_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count)
{
    return process_entry(ctx, file, buf, count, 0);
}

