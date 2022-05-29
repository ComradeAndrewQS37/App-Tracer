#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>


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



//called when new tcpv4 connection is established
int tcp_v4_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
	FILTER_PID
	
	//start tracing this socket
	u64 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &sk);
	
	return 0;
};


//called when package exchange through tcpv4 connection is finished
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

int trace_close_entry(struct pt_regs *ctx, struct sock *skp)
{
  
  	FILTER_PID
  	
	u8 oldstate = skp->sk_state;
  	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV){
      		return 0;
      	}

 
      
      	u32 daddr = skp->__sk_common.skc_daddr;
      	u32 saddr = skp->__sk_common.skc_rcv_saddr;
      
     	if(saddr==0 || daddr == 0)
	{
		return 0;
	}
	struct inet_sock *i_skp = (struct inet_sock *)skp;
  	u16 sport = i_skp->inet_sport;
  	u16 dport = skp->__sk_common.skc_dport;
  	
	// save this info
	struct ipv4_data_t new_event = {};
	
	new_event.type = CLOSE;
	new_event.ts_ms = bpf_ktime_get_ns() / 1000000;
	new_event.pid = bpf_get_current_pid_tgid() >> 32;
	new_event.daddr = daddr;
	new_event.saddr = saddr;
	new_event.dport = ntohs(dport);
	new_event.sport = ntohs(sport);
	
	ipv4_events.perf_submit(ctx, &new_event, sizeof(new_event));
  

  	return 0;
};

