/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H


#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>
#include <uapi/linux/tcp.h>

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}

static inline struct tcphdr *inner_tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_inner_transport_header(skb);
}

static inline unsigned int inner_tcp_hdrlen(const struct sk_buff *skb)
{
	return inner_tcp_hdr(skb)->doff * 4;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* TCP Fast Open */
#define TCP_FASTOPEN_COOKIE_MIN	4	/* Min Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_MAX	16	/* Max Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_SIZE 8	/* the size employed by this impl. */

/* TCP Fast Open Cookie as stored in memory */
struct tcp_fastopen_cookie {
	s8	len;
	u8	val[TCP_FASTOPEN_COOKIE_MAX];
};

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

/*These are used to set the sack_ok field in struct tcp_options_received */
#define TCP_SACK_SEEN     (1 << 0)   /*1 = peer is SACK capable, */
#define TCP_FACK_ENABLED  (1 << 1)   /*1 = FACK is enabled locally*/
#define TCP_DSACK_SEEN    (1 << 2)   /*1 = DSACK was received from peer*/

// 用来保存接收到的TCP选项信息，如时间戳、SACK等；同时标志对端支持的特性，如对端是否
// 支持窗口扩大因子，是否支持SACK等。
struct tcp_options_received {
/*	PAWS/RTTM data	*/
  // 记录从接收到的段中取出时间戳设置到ts_recent的时间，用于检测ts_recent的有效性；
  // 如果自从该时间之后已经超过了24天时间，则认为ts_recent无效。
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */

  // 下一个待发送的TCP段中的时间戳回显值。当一个含有最后发送ACK中确认序号的段到达时，
  // 该段中的时间戳被保存在ts_recent中。而下一个待发送的TCP段的时间戳是由SKB中的TCP
  // 控制块的成员when填入的，when字段值是由协议栈取系统时间变量jiffies的低32位。
	u32	ts_recent;	/* Time stamp to echo next		*/

  // 保存最近一次接收到对端的TCP段的时间戳选项中的时间戳值。
	u32	rcv_tsval;	/* Time stamp value             	*/

  // 保存最近一次接收到对端的TCP段的时间戳选项中的时间戳回显应答。
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/

  // 标识最近一次接收到的TCP段是否存在TCP时间戳选项，1/0
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/

  // 标识TCP连接是否启用时间戳选项。在TCP建立连接过程中如果接收到TCP段中有时间戳选项 ，
  // 则说明对端也支持时间戳选项，这时tstamp_ok会被置为1，表示该连接支持时间戳选项，在随后的
  // 数据传输中，TCP首部中都会带有时间戳选项。
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/

  // 标识下次发送的段中SACK选项（选择性确认）是否存在D-SACK（duplicate-SACK）
		dsack : 1,	/* D-SACK is scheduled			*/

    // 标识接收方是否支持窗口扩大因子，只能出现在SYN段中。
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/

    // 标识接收方是否支持SACK，只有0、1两种值。因为sack_ok占有4位，因此在正常带有负荷的段中，
    // 其余位还有其他的含义：第一位表示是否启用FACK拥塞避免，第二位表示在SACK选项中是否存在D-SACK，第三位保留
		sack_ok : 4,	/* SACK seen on SYN packet		*/

    // 发送窗口扩大因此，即要把TCP首部滑动窗口大小左移snd_wscale位后，才是真正的滑动窗口大小。
    // 在TCP首部中，滑动窗口大小是16位的，而snd_wscale的值最大只能为14，所以滑动窗口值最大可被
    // 扩展到30位。在协议栈的实现中，可以看到窗口大小被置为5840，扩大因子为2，即实际的窗口大小为5840<<2=23360KB。
		snd_wscale : 4,	/* Window scaling received from sender	*/

    // 接收窗口扩大因子
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/

  // 下一个待发送的段中SACK选项的SACK块
	u8	num_sacks;	/* Number of SACK bloocks		*/

  // 为用户设置的MSS上限，与建立连接时SYN段中的MSS，两者之间的最小值为该连接的MSS上限，存储在mss_clamp中。
  // 使用setsockopt/getsockopt系统调用TCP_MAXSEG选项设置、获取，有效值在8-32767之间。
	u16	user_mss;	/* mss requested by user in ioctl	*/

  // 该连接的对端MSS上限。user_mss与建立连接时SYN段中的MSS，两者之间的最小值做为该连接的MSS上限。
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

static inline void tcp_clear_options(struct tcp_options_received *rx_opt)
{
	rx_opt->tstamp_ok = rx_opt->sack_ok = 0;
	rx_opt->wscale_ok = rx_opt->snd_wscale = 0;
}

/* This is the max number of SACKS that we'll generate and process. It's safe
 * to increase this, although since:
 *   size = TCPOLEN_SACK_BASE_ALIGNED (4) + n * TCPOLEN_SACK_PERBLOCK (8)
 * only four options will fit in a standard TCP header */
#define TCP_NUM_SACKS 4

struct tcp_request_sock_ops;

// tcp_request_sock结构做为TCP连接请求块，用来保存双方的初始序号、双方的端口号及
// IP地址、TCP选项，如是否支持窗口扩大因子、是否支持SACK等，并控制连接的建立。
struct tcp_request_sock {
	struct inet_request_sock 	req;
#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	const struct tcp_request_sock_ops *af_specific;
#endif
	struct sock			*listener; /* needed for TFO */
  // 客户端的初始序列号，接收到客户端连接请求时的SYN段的序号
	u32				rcv_isn;
  // 服务端的初始序号，服务端发送SYN+ACK段的序号
	u32				snt_isn;
	u32				snt_synack; /* synack sent time */
	u32				rcv_nxt; /* the ack # by SYNACK. For
						  * FastOpen it's the seq#
						  * after data-in-SYN.
						  */
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
  // TCP首部长度，包括TCP选项
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
  // 记录该套接字发送到网络设备段的长度，在不支持TSO的情况下，其值等于MSS；
  // 而如果网卡支持TSO并且使用TSO进行发送，则需要重新计算
	u16	xmit_size_goal_segs; /* Goal for segmenting output packets */

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
  // 首部预测标志，会在发送和接收SYN，更新窗口或其他恰当的时候，设置该标志。
  // 该标志和时间戳以及序列号等因素一样是判断执行快速路径还是慢速路径的条件之一
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
  // 等待接收的下一个TCP段的序号，每接收一个TCP段之后都会更新该值
 	u32	rcv_nxt;	/* What we want to receive next 	*/
	u32	copied_seq;	/* Head of yet unread data		*/
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
  // 等待发送的下一个TCP段的序号
 	u32	snd_nxt;	/* Next sequence we send		*/

  // 在输出的段中，最早一个未确认的序号
 	u32	snd_una;	/* First byte we want an ack for	*/
  // 最近发送的小包（小于MSS的段）的最后一个字节序号，在成功发送段后，
  // 如果报文小于MSS，即更新该字段，主要用来判断是否启用nagle算法
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
  // 最近一次收到ACK段的时间，用于TCP保活
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
  // 最近一次发送数据包的时间，主要用于拥塞窗口的设置
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */

	u32	tsoffset;	/* timestamp offset */

	struct list_head tsq_node; /* anchor in tsq_tasklet.head list */
	unsigned long	tsq_flags;

	/* Data for direct copy to user */
  // 用来控制复制数据给用户进程的控制块
	struct {
    // 如果未启用tcp_low_latency，TCP段将首先缓存到此队列，直到进程
    // 主动读取时才真正地接收到接收队列中处理
		struct sk_buff_head	prequeue;
    // 未启用tcp_low_latency的情况下，当前正在读取TCP流的进程，如果
    // 为NULL则表示暂时没有进程对其进行读取
		struct task_struct	*task;
    // 未启用tcp_low_latency的情况下，用来存放数据的用户空间地址，在接收
    // 处理TCP段时直接复制到用户空间
		struct iovec		*iov;
    // prequeue队列当前消耗的内存
		int			memory;
    // 用户缓存中当前可使用的缓存大小，由recv等系统调用的len参数初始化
		int			len;
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

  // 记录更新发送窗口的那个ACK段的序号，用来判断是否需要更新窗口，如果后续
  // 收到的ACK段的序号大于snd_wl1，则说明需要更新窗口，否则无需更新
	u32	snd_wl1;	/* Sequence for window update		*/
  // 接收方提供的接收窗口大小，即发送方发送窗口的大小
	u32	snd_wnd;	/* The window we expect to receive	*/
  // 接收方通告过的最大接收窗口值
	u32	max_window;	/* Maximal window ever seen from peer	*/
  // 发送方当前有效MSS，参见SOL_TCP选项
	u32	mss_cache;	/* Cached effective mss, not including SACKS */

  // 滑动窗口最大值，滑动窗口大小在变化过程中始终不能超出该值。
  // 在TCP建立连接时，该字段被初始化，置为最大的16位整数左移窗口的
  // 扩大因子的位数。因为滑动窗口在TCP首部以16位表示，window_clamp
  // 太大会导致滑动窗口不能在TCP首部中表示
	u32	window_clamp;	/* Maximal window to advertise		*/
  // 当前接收窗口大小的阈值，该字段与rcv_wnd两者配合，达到滑动窗口大小缓慢
  // 增长的效果：其初始值为rcv_wnd，当本地套接字收到段，并满足一定条件时，
  // 会递增该字段，到下一个发送数据组建TCP首部时，需通告对端当前接收窗口大小，
  // 此时更新rcv_wnd，而rcv_wnd的值不能超过rcv_ssthresh
	u32	rcv_ssthresh;	/* Current window clamp			*/

	u16	advmss;		/* Advertised MSS			*/
	u8	unused;
	u8	nonagle     : 4,/* Disable Nagle algorithm?             */
		thin_lto    : 1,/* Use linear timeouts for thin streams */
		thin_dupack : 1,/* Fast retransmit on first dupack      */
		repair      : 1,
		frto        : 1;/* F-RTO (RFC5682) activated in CA_Loss */
	u8	repair_queue;
	u8	do_early_retrans:1,/* Enable RFC5827 early-retransmit  */
		syn_data:1,	/* SYN includes data */
		syn_fastopen:1,	/* SYN includes Fast Open option */
		syn_data_acked:1;/* data in SYN is acked by SYN-ACK */
	u32	tlp_high_seq;	/* snd_nxt at the time of TLP retransmit. */

/* RTT measurement */
  // 平滑的RTT，为避免浮点计算，将其放大8倍后存储的
	u32	srtt;		/* smoothed round trip time << 3	*/
  // RTT的平均偏差，由RTT与RTT的均值偏差绝对值加权平均而得到的，越大说明RTT抖动的越厉害
	u32	mdev;		/* medium deviation			*/
  // 跟踪每次发送窗口内的段被全部确认过程中，RTT平均偏差的最大值，描述RTT抖动的最大范围
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
  // 平滑的RTT平均偏差，由mdev计算得到，用来计算RTO
	u32	rttvar;		/* smoothed mdev_max			*/
  // 记录SND.UNA，用来计算RTO时比较SND.UNA是否已经被更新了，
  // 如果被SND.UNA更新，需要同时更新rttvar
	u32	rtt_seq;	/* sequence number to update rttvar	*/

  // 从发送队列发出而未得到确认TCP段的数目（即SND.NXT-SND.UNA），该值是动态的，
  // 当有新的段发出或有新的确认收到都会增加或减小该值
	u32	packets_out;	/* Packets which are "in flight"	*/
  // 重传还未得到确认的TCP段数目
	u32	retrans_out;	/* Retransmitted packets out		*/

	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	ecn_flags;	/* ECN status bits.			*/
	u8	reordering;	/* Packet reordering metric.		*/
	u32	snd_up;		/* Urgent pointer		*/

  // 保活探测的次数，最大值为127，参见TCP_KEEPCNT选项
	u8	keepalive_probes; /* num of allowed keep alive probes	*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
  // 存储接收到的TCP选项
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
  // 拥塞控制时慢启动的阈值
 	u32	snd_ssthresh;	/* Slow start size threshold		*/
  // 当前拥塞窗口大小
 	u32	snd_cwnd;	/* Sending congestion window		*/
  // 自从上次调整拥塞窗口到目前为止接收到的总ACK段数，如果该字段为0，
  // 则说明已经调整了拥塞窗口，且到目前为止还没有接收到ACK段。
  // 调整拥塞窗口之后，每接收到一个ACK段就会使snd_cwnd_cnt+1
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
  // 允许的最大拥塞窗口值。初始值为65535，之后在接收SYN和ACK段时，会根据条件确定
  // 是否从路由配置项预读信息更新该字段，最后在TCP链接复位前，将更新后的值根据某种算法
  // 计算后再更新回相对应的路由配置项中，便于连接使用
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
  // 当应用程序限制时，记录当前从发送队列发出而未得到确认的段数，用于在检验拥塞窗口时
  // 调节拥塞窗口，避免拥塞窗口失效。
	u32	snd_cwnd_used;
  // 记录最近一次检验拥塞窗口的时间。在拥塞期间，接收到ACK后进行拥塞窗口的检验。
  // 而在非拥塞期间，为了防止由于应用程序限制而造成拥塞窗口失效，因此在成功发送段后，
  // 如果有必要也会检验拥塞窗口
	u32	snd_cwnd_stamp;

	u32	prior_cwnd;	/* Congestion window at start of Recovery. */
	u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
	u32	prr_out;	/* Total number of pkts sent during Recovery. */

  // 当前接收窗口的大小
 	u32	rcv_wnd;	/* Current receiver window		*/
  // 已加入到发送队列中的最后一个字节序号
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	notsent_lowat;	/* TCP_NOTSENT_LOWAT */
  // 通常情况下表示已经真正发送出去的最后一个字节序号；但有时也可能表示
  // 期望发送出去的最后一个字节序号，如启用nagle算法之后，或在发送持续探测段后
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	lost_out;	/* Lost packets			*/
	u32	sacked_out;	/* SACK'd packets			*/
	u32	fackets_out;	/* FACK'd packets			*/
	u32	tso_deferred;

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;
	struct sk_buff *retransmit_skb_hint;

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

	/* SACKs data, these 2 need to be together (see tcp_options_write) */
  // 存储用于对端SACK的信息。duplicate_sack存储D-SACK信息，selective_acks存储
  // SACK信息，在回复SACK时会从中取出D-SACK和SACK信息，而在处理接收到乱序的段时，
  // 会向这两个字段中填入相应的信息。
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

  // 存储接收到的SACK选项信息
	struct tcp_sack_block recv_sack_cache[4];

	struct sk_buff *highest_sack;   /* skb just after the highest
					 * skb with SACKed bit set
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */

  // 一般在拥塞状态没有撤销或没有进入loss状态时，在重传队列中，缓存上一次
  // 标记分牌未丢失的最后一个段，主要为了加速对重传队列的标记操作。
	int     lost_cnt_hint;
	u32     retransmit_high;	/* L-bits may be on up to this seqno */

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */

	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* tracking retrans started here. */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	total_retrans;	/* Total retransmits for entire connection */

	u32	urg_seq;	/* Seq of received urgent pointer */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */

	int			linger2;

/* Receiver side RTT estimation */
	struct {
		u32	rtt;
		u32	seq;
		u32	time;
	} rcv_rtt_est;

/* Receiver queue space */
	struct {
		int	space;
		u32	seq;
		u32	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;
	u32	mtu_info; /* We received an ICMP_FRAG_NEEDED / ICMPV6_PKT_TOOBIG
			   * while socket was owned by user.
			   */

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	__rcu *md5sig_info;
#endif

/* TCP fastopen related information */
	struct tcp_fastopen_request *fastopen_req;
	/* fastopen_rsk points to request_sock that resulted in this big
	 * socket. Used to retransmit SYNACKs etc.
	 */
	struct request_sock *fastopen_rsk;
};

enum tsq_flags {
	TSQ_THROTTLED,
	TSQ_QUEUED,
	TCP_TSQ_DEFERRED,	   /* tcp_tasklet_func() found socket was owned */
	TCP_WRITE_TIMER_DEFERRED,  /* tcp_write_timer() found socket was owned */
	TCP_DELACK_TIMER_DEFERRED, /* tcp_delack_timer() found socket was owned */
	TCP_MTU_REDUCED_DEFERRED,  /* tcp_v{4|6}_err() could not call
				    * tcp_v{4|6}_mtu_reduced()
				    */
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_offset;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key	  *tw_md5_key;
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

static inline bool tcp_passive_fastopen(const struct sock *sk)
{
	return (sk->sk_state == TCP_SYN_RECV &&
		tcp_sk(sk)->fastopen_rsk != NULL);
}

static inline bool fastopen_cookie_present(struct tcp_fastopen_cookie *foc)
{
	return foc->len != -1;
}

extern void tcp_sock_destruct(struct sock *sk);

static inline int fastopen_init_queue(struct sock *sk, int backlog)
{
	struct request_sock_queue *queue =
	    &inet_csk(sk)->icsk_accept_queue;

	if (queue->fastopenq == NULL) {
		queue->fastopenq = kzalloc(
		    sizeof(struct fastopen_queue),
		    sk->sk_allocation);
		if (queue->fastopenq == NULL)
			return -ENOMEM;

		sk->sk_destruct = tcp_sock_destruct;
		spin_lock_init(&queue->fastopenq->lock);
	}
	queue->fastopenq->max_qlen = backlog;
	return 0;
}

#endif	/* _LINUX_TCP_H */
