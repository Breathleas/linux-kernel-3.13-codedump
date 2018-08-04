/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

#include <linux/module.h>
#include <linux/gfp.h>
#include <net/tcp.h>

int sysctl_tcp_syn_retries __read_mostly = TCP_SYN_RETRIES;
int sysctl_tcp_synack_retries __read_mostly = TCP_SYNACK_RETRIES;
int sysctl_tcp_keepalive_time __read_mostly = TCP_KEEPALIVE_TIME;
int sysctl_tcp_keepalive_probes __read_mostly = TCP_KEEPALIVE_PROBES;
int sysctl_tcp_keepalive_intvl __read_mostly = TCP_KEEPALIVE_INTVL;
int sysctl_tcp_retries1 __read_mostly = TCP_RETR1;
int sysctl_tcp_retries2 __read_mostly = TCP_RETR2;
int sysctl_tcp_orphan_retries __read_mostly;
int sysctl_tcp_thin_linear_timeouts __read_mostly;

static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

	tcp_done(sk);
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONTIMEOUT);
}

/* Do not allow orphaned sockets to eat all our resources.
 * This is direct violation of TCP specs, but it is required
 * to prevent DoS attacks. It is called when a retransmission timeout
 * or zero probe timeout occurs on orphaned socket.
 *
 * Criteria is still not confirmed experimentally and may change.
 * We kill the socket, if:
 * 1. If number of orphaned sockets exceeds an administratively configured
 *    limit.
 * 2. If we have strong memory pressure.
 */
static int tcp_out_of_resources(struct sock *sk, int do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int shift = 0;

	/* If peer does not open window for long time, or did not transmit
	 * anything for long time, penalize it. */
	if ((s32)(tcp_time_stamp - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		shift++;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		shift++;

	if (tcp_check_oom(sk, shift)) {
		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = 1;
		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}
	return 0;
}

/* Calculate maximal number or retries on an orphaned socket. */
static int tcp_orphan_retries(struct sock *sk, int alive)
{
	int retries = sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

static void tcp_mtu_probing(struct inet_connection_sock *icsk, struct sock *sk)
{
	/* Black hole detection */
	if (sysctl_tcp_mtu_probing) {
		if (!icsk->icsk_mtup.enabled) {
			icsk->icsk_mtup.enabled = 1;
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		} else {
			struct tcp_sock *tp = tcp_sk(sk);
			int mss;

			mss = tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low) >> 1;
			mss = min(sysctl_tcp_base_mss, mss);
			mss = max(mss, 68 - tp->tcp_header_len);
			icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		}
	}
}

/* This function calculates a "timeout" which is equivalent to the timeout of a
 * TCP connection after "boundary" unsuccessful, exponentially backed-off
 * retransmissions with an initial RTO of TCP_RTO_MIN or TCP_TIMEOUT_INIT if
 * syn_set flag is set.
 */
static bool retransmits_timed_out(struct sock *sk,
				  unsigned int boundary,
				  unsigned int timeout,
				  bool syn_set)
{
	unsigned int linear_backoff_thresh, start_ts;
	unsigned int rto_base = syn_set ? TCP_TIMEOUT_INIT : TCP_RTO_MIN;

	if (!inet_csk(sk)->icsk_retransmits)
		return false;

	if (unlikely(!tcp_sk(sk)->retrans_stamp))
		start_ts = TCP_SKB_CB(tcp_write_queue_head(sk))->when;
	else
		start_ts = tcp_sk(sk)->retrans_stamp;

	if (likely(timeout == 0)) {
		linear_backoff_thresh = ilog2(TCP_RTO_MAX/rto_base);

		if (boundary <= linear_backoff_thresh)
			timeout = ((2 << boundary) - 1) * rto_base;
		else
			timeout = ((2 << linear_backoff_thresh) - 1) * rto_base +
				(boundary - linear_backoff_thresh) * TCP_RTO_MAX;
	}
	return (tcp_time_stamp - start_ts) >= timeout;
}

/* A write timeout has occurred. Process the after effects. */
// 写重传发生，处理
static int tcp_write_timeout(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int retry_until;
	bool do_reset, syn_set = false;

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
    // 状态为SYN_SENT或者SYN_RECV的超时，说明是建立连接情况下的超时。
		if (icsk->icsk_retransmits) {
      // 需要检测使用的路由器
			dst_negative_advice(sk);
			if (tp->syn_fastopen || tp->syn_data)
				tcp_fastopen_cache_set(sk, 0, NULL, true);
		}
    // 获取重试次数的最大值
		retry_until = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
		syn_set = true;
	} else {
		if (retransmits_timed_out(sk, sysctl_tcp_retries1, 0, 0)) {
      // 重传次数达到tcp_retries1时，需要进行黑洞检测。
			/* Black hole detection */
			tcp_mtu_probing(icsk, sk);
      // 完成黑洞检测后还需要检测使用的路由缓存项。
			dst_negative_advice(sk);
		}

		retry_until = sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {
      // 如果当前套接口连接已断开并即将关闭，则需要对当前使用的资源进行检测。
      // 当前的孤儿套接口数量达到tcp_max_orphans或者当前已使用内存达到硬性限制时，
      // 需要即刻关闭该套接口，这虽然不符合TCP的规范，但是为了防止DDOS攻击必须这么处理。
			const int alive = (icsk->icsk_rto < TCP_RTO_MAX);

			retry_until = tcp_orphan_retries(sk, alive);
			do_reset = alive ||
				!retransmits_timed_out(sk, retry_until, 0, 0);

			if (tcp_out_of_resources(sk, do_reset))
				return 1;
		}
	}

  // 当重传次数达到建立连接重传上线、超时重传上限或确认连接异常期间重试上限或三种上限之一，
  // 都必须关闭套接口，并且需要报告相应错误。
	if (retransmits_timed_out(sk, retry_until,
				  syn_set ? 0 : icsk->icsk_user_timeout, syn_set)) {
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}
	return 0;
}

void tcp_delack_timer_handler(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

  // 回收缓存
	sk_mem_reclaim_partial(sk);

  // 如果TCP状态为CLOSE，或者没有启动延时发送ACK定时器，则无需进一步处理
	if (sk->sk_state == TCP_CLOSE || !(icsk->icsk_ack.pending & ICSK_ACK_TIMER))
		goto out;

  // 超时时间未到，重新复位定时器
	if (time_after(icsk->icsk_ack.timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
		goto out;
	}

  // 检测完成后，正式进入延迟确认处理之前，需要去掉ICSK_ACK_TIMER标志。
	icsk->icsk_ack.pending &= ~ICSK_ACK_TIMER;

	if (!skb_queue_empty(&tp->ucopy.prequeue)) {
    // 如果ucopy控制块中的prequeue队列不为空，则通过sk_backlog_rcv接口处理
    // sk_backlog_rcv队列中的SKB。TCP中sk_backlog_rcv接口为tcp_v4_do_rcv
		struct sk_buff *skb;

		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSCHEDULERFAILED);

		while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
			sk_backlog_rcv(sk, skb);

		tp->ucopy.memory = 0;
	}

	if (inet_csk_ack_scheduled(sk)) {
    // 如果此时有ACK需要发送，则调用tcp_send_ack构造并发送ACK段，在发送ACK段之前
    // 需要先离开pingpong模式，并重新设定延时确认的估算值
		if (!icsk->icsk_ack.pingpong) {
			/* Delayed ACK missed: inflate ATO. */
			icsk->icsk_ack.ato = min(icsk->icsk_ack.ato << 1, icsk->icsk_rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			icsk->icsk_ack.pingpong = 0;
			icsk->icsk_ack.ato      = TCP_ATO_MIN;
		}
		tcp_send_ack(sk);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKS);
	}

out:
	if (sk_under_memory_pressure(sk))
		sk_mem_reclaim(sk);
}

// 延时ACK定时器在TCP收到必须被确认但无需马上发出确认的段时设定，TCP在200ms后发送确认响应，
// 如果在这200ms内，有数据要在该连接上发送，延时ACK响应就可以随数据一起发送回对端，称为捎带确认。
static void tcp_delack_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
    // 如果传输控制块没有被用户进程锁定，则进行处理
		tcp_delack_timer_handler(sk);
	} else {
    // 重新设置定时器超时时间，同时设置blocked标记
		inet_csk(sk)->icsk_ack.blocked = 1;
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOCKED);
		/* deleguate our work to tcp_release_cb() */
		if (!test_and_set_bit(TCP_DELACK_TIMER_DEFERRED, &tcp_sk(sk)->tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

// 探测定时器在对端通告接收窗口为0，阻止TCP继续发送时设定。
// 由于对端发送的窗口不可靠（只有数据才会确认，ACK不会被确认），允许TCP继续发送数据的
// 后续窗口更新可能丢失。因此，如果TCP有数据要发送，而对端通知接收窗口为0，则持续定时器启动，
// 超时后向对端发送1字节的数据，以判断对端接收窗口是否已打开。与重传定时器类似，探测定时器的超时值
// 也是动态计算的，取决于连接的往返时间，在5~60s之间取值。
static void tcp_probe_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;

  // 由于探测定时器会周期性的发送探测段，因此如果存在发送出去但未被确认的段，或者在发送队列中
  // 还有待发送的段，则无需另外组织探测段了，将icsk_probes_out清零后返回。
	if (tp->packets_out || !tcp_send_head(sk)) {
		icsk->icsk_probes_out = 0;
		return;
	}

	/* *WARNING* RFC 1122 forbids this
	 *
	 * It doesn't AFAIK, because we kill the retransmit timer -AK
	 *
	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
	 * this behaviour in Solaris down as a bug fix. [AC]
	 *
	 * Let me to explain. icsk_probes_out is zeroed by incoming ACKs
	 * even if they advertise zero window. Hence, connection is killed only
	 * if we received no ACKs for normal connection timeout. It is not killed
	 * only because window stays zero for some time, window may be zero
	 * until armageddon and even later. We are in full accordance
	 * with RFCs, only probe timer combines both retransmission timeout
	 * and probe timeout in one bottle.				--ANK
	 */
  // 获取确定断开连接前持续定时器周期性发送TCP段的数目上限，用于持续定时器发出段数量的探测。
	max_probes = sysctl_tcp_retries2;

	if (sock_flag(sk, SOCK_DEAD)) { // 处理连接已断开，套接口即将关闭的情况
    // TCP协议规定RTT的最大值为120s(TCP_RTO_MAX)，因此可以通过将指数退避算法得出的
    // 超时时间与RTT最大值相比，来判断是否需要给对方发送RST
		const int alive = ((icsk->icsk_rto << icsk->icsk_backoff) < TCP_RTO_MAX);

    // 如果连接已断开，套接口即将关闭，则获取在关闭本端TCP连接前重试次数的上限。
		max_probes = tcp_orphan_retries(sk, alive);

    // 释放资源，如果该套接口在释放过程中被关闭，则无需再发送持续探测段了。
		if (tcp_out_of_resources(sk, alive || icsk->icsk_probes_out <= max_probes))
			return;
	}

	if (icsk->icsk_probes_out > max_probes) {
    // 如果持续定时器或保活定时器周期性发送出但未被确认的TCP段数目达到上限，
    // 则做出错处理，同时关闭TCP套接口
		tcp_write_err(sk);
	} else {
		/* Only send another probe if we didn't close things up. */
    // 再一次发送持续探测段
		tcp_send_probe0(sk);
	}
}

/*
 *	Timer for Fast Open socket to retransmit SYNACK. Note that the
 *	sk here is the child socket, not the parent (listener) socket.
 */
static void tcp_fastopen_synack_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int max_retries = icsk->icsk_syn_retries ? :
	    sysctl_tcp_synack_retries + 1; /* add one more retry for fastopen */
	struct request_sock *req;

	req = tcp_sk(sk)->fastopen_rsk;
	req->rsk_ops->syn_ack_timeout(sk, req);

	if (req->num_timeout >= max_retries) {
		tcp_write_err(sk);
		return;
	}
	/* XXX (TFO) - Unlike regular SYN-ACK retransmit, we ignore error
	 * returned from rtx_syn_ack() to make it more persistent like
	 * regular retransmit because if the child socket has been accepted
	 * it's not good to give up too easily.
	 */
	inet_rtx_syn_ack(sk, req);
	req->num_timeout++;
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
			  TCP_TIMEOUT_INIT << req->num_timeout, TCP_RTO_MAX);
}

/*
 *	The TCP retransmit timer.
 */

void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (tp->fastopen_rsk) {
		WARN_ON_ONCE(sk->sk_state != TCP_SYN_RECV &&
			     sk->sk_state != TCP_FIN_WAIT1);
		tcp_fastopen_synack_timer(sk);
		/* Before we receive ACK to our SYN-ACK don't retransmit
		 * anything else (e.g., data or FIN segments).
		 */
		return;
	}

  // 如果发送队列输出的段都已经得到确认，无需重传处理
	if (!tp->packets_out)
		goto out;

	WARN_ON(tcp_write_queue_empty(sk));

	tp->tlp_high_seq = 0;

  // 处理发送窗口已关闭，套接口不在DEAD状态且TCP状态不处于连接过程中的情况
	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
		struct inet_sock *inet = inet_sk(sk);
		if (sk->sk_family == AF_INET) {
			LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n"),
				       &inet->inet_daddr,
				       ntohs(inet->inet_dport), inet->inet_num,
				       tp->snd_una, tp->snd_nxt);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (sk->sk_family == AF_INET6) {
			LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n"),
				       &sk->sk_v6_daddr,
				       ntohs(inet->inet_dport), inet->inet_num,
				       tp->snd_una, tp->snd_nxt);
		}
#endif
    // 在重传过程中，如果超过重传超时上限TCP_RTO_MAX(120s)还没有收到对方的确认，
    // 则认为有错误发生。调用tcp_write_err报告错误并关闭套接口
		if (tcp_time_stamp - tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(sk);
			goto out;
		}
    // 否则进入拥塞控制的LOSS状态，并重新传送重传队列的第一个段。
    // 此外由于发生了重传，传输控制块中目的路由项缓存需要更新，因此将其清除。
    // 最后跳转到out_reset_timer标签做处理。
		tcp_enter_loss(sk, 0);
		tcp_retransmit_skb(sk, tcp_write_queue_head(sk));
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

  // 发生重传后，需要检测当前的资源使用情况和重传的次数。
  // 如果重传的次数达到上限，则需要报告错误并强行关闭套接口。
  // 如果只是使用的资源达到使用的上限，则不进行此次重传。
	if (tcp_write_timeout(sk))
		goto out;

  // 如果重传次数为0，说明刚进入重传阶段，根据不同的拥塞状态进行数据统计
	if (icsk->icsk_retransmits == 0) {
		int mib_idx;

		if (icsk->icsk_ca_state == TCP_CA_Recovery) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKRECOVERYFAIL;
			else
				mib_idx = LINUX_MIB_TCPRENORECOVERYFAIL;
		} else if (icsk->icsk_ca_state == TCP_CA_Loss) {
			mib_idx = LINUX_MIB_TCPLOSSFAILURES;
		} else if ((icsk->icsk_ca_state == TCP_CA_Disorder) ||
			   tp->sacked_out) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKFAILURES;
			else
				mib_idx = LINUX_MIB_TCPRENOFAILURES;
		} else {
			mib_idx = LINUX_MIB_TCPTIMEOUTS;
		}
		NET_INC_STATS_BH(sock_net(sk), mib_idx);
	}

	tcp_enter_loss(sk, 0);

  // 如果重传队列上的第一个SKB失败，则复位重传定时器，等待下一次重传。
	if (tcp_retransmit_skb(sk, tcp_write_queue_head(sk)) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!icsk->icsk_retransmits)
			icsk->icsk_retransmits = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  min(icsk->icsk_rto, TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
  // 发送成功后，递增指数退避算法指数icsk_backoff和累计重传次数icsk_retransmits
	icsk->icsk_backoff++;
	icsk->icsk_retransmits++;

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	if (sk->sk_state == TCP_ESTABLISHED &&
	    (tp->thin_lto || sysctl_tcp_thin_linear_timeouts) &&
	    tcp_stream_is_thin(tp) &&
	    icsk->icsk_retransmits <= TCP_THIN_LINEAR_RETRIES) {
		icsk->icsk_backoff = 0;
		icsk->icsk_rto = min(__tcp_set_rto(tp), TCP_RTO_MAX);
	} else {
		/* Use normal (exponential) backoff */
		icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	}
  // 完成重传后，需要重设重传超时时间，然后复位重传定时器，等待下次重传。
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, icsk->icsk_rto, TCP_RTO_MAX);
	if (retransmits_timed_out(sk, sysctl_tcp_retries1 + 1, 0, 0))
		__sk_dst_reset(sk);

out:;
}

void tcp_write_timer_handler(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int event;

  // 状态为CLOSE或者没有定义定时器事件，则不用处理
	if (sk->sk_state == TCP_CLOSE || !icsk->icsk_pending)
		goto out;

  // 未到定时器超时时间，无需处理，重新设置定时器超时时间
	if (time_after(icsk->icsk_timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
		goto out;
	}

	event = icsk->icsk_pending;

  // 由于这个定时器处理多个定时器事件，所以要做区分处理
	switch (event) {
	case ICSK_TIME_EARLY_RETRANS:
		tcp_resume_early_retransmit(sk);
		break;
	case ICSK_TIME_LOSS_PROBE:
		tcp_send_loss_probe(sk);
		break;
	case ICSK_TIME_RETRANS:
    // 重传定时器
		icsk->icsk_pending = 0;
		tcp_retransmit_timer(sk);
		break;
	case ICSK_TIME_PROBE0:
    // 持续定时器
		icsk->icsk_pending = 0;
		tcp_probe_timer(sk);
		break;
	}

out:
	sk_mem_reclaim(sk);
}

static void tcp_write_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		tcp_write_timer_handler(sk);
	} else {
		/* deleguate our work to tcp_release_cb() */
		if (!test_and_set_bit(TCP_WRITE_TIMER_DEFERRED, &tcp_sk(sk)->tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 *	Timer for listening sockets
 */

static void tcp_synack_timer(struct sock *sk)
{
	inet_csk_reqsk_queue_prune(sk, TCP_SYNQ_INTERVAL,
				   TCP_TIMEOUT_INIT, TCP_RTO_MAX);
}

void tcp_syn_ack_timeout(struct sock *sk, struct request_sock *req)
{
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPTIMEOUTS);
}
EXPORT_SYMBOL(tcp_syn_ack_timeout);

void tcp_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val)
		inet_csk_delete_keepalive_timer(sk);
}

// 保活定时器
static void tcp_keepalive_timer (unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 elapsed;

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);
  // 如果用户持有该套接字，则重置该保活定时器等待再次尝试
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		inet_csk_reset_keepalive_timer (sk, HZ/20);
		goto out;
	}

	if (sk->sk_state == TCP_LISTEN) {
		tcp_synack_timer(sk);
		goto out;
	}

  // 处理FIN_WAIT_2状态的定时器，此时状态必须是FIN_WAIT_2且接口状态为DEAD
	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) {
		if (tp->linger2 >= 0) {
      // 计算停留在FIN_WAIT_2状态的时间
			const int tmo = tcp_fin_time(sk) - TCP_TIMEWAIT_LEN;

			if (tmo > 0) {  // 如果大于0
        // 调用tcp_time_wait继续处理
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
    // 否则RST关闭连接
		tcp_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}

  // 如果没有启用保活功能，或者状态为CLOSE，则返回
	if (!sock_flag(sk, SOCK_KEEPOPEN) || sk->sk_state == TCP_CLOSE)
		goto out;

	elapsed = keepalive_time_when(tp);

	/* It is alive without keepalive 8) */
  // 如果有已输出未确认的段，或者发送队列中还存在未发送的段，则无需做处理，
  // 只需重新设定保活定时器的超时时间
	if (tp->packets_out || tcp_send_head(sk))
		goto resched;

  // 获取最近一次收到段到目前为止的时间，即空闲持续时间。
	elapsed = keepalive_time_elapsed(tp);

	if (elapsed >= keepalive_time_when(tp)) {
    // 如果持续空闲时间超过了允许时间
		/* If the TCP_USER_TIMEOUT option is enabled, use that
		 * to determine when to timeout instead.
		 */
		if ((icsk->icsk_user_timeout != 0 &&
		    elapsed >= icsk->icsk_user_timeout && // 
		    icsk->icsk_probes_out > 0) ||
		    (icsk->icsk_user_timeout == 0 &&
		    icsk->icsk_probes_out >= keepalive_probes(tp))) { // 已发送的探测段数超过了系统默认的允许数tcp_keepalive_probes
      // 需要断开连接，给对方发送RST段。并报告相应错误，关闭相应的传输控制块
			tcp_send_active_reset(sk, GFP_ATOMIC);
			tcp_write_err(sk);
			goto out;
		}
    // 发送保活段，并计算下一次激活保活定时器的时间
		if (tcp_write_wakeup(sk) <= 0) {
			icsk->icsk_probes_out++;
			elapsed = keepalive_intvl_when(tp);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = TCP_RESOURCE_PROBE_INTERVAL;
		}
	} else {
    // 到这里是持续空闲时间没有超过允许时间的情况
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
    // 重新计算下次激活保活定时器的时间
		elapsed = keepalive_time_when(tp) - elapsed;
	}

  // 回收缓存
	sk_mem_reclaim(sk);

resched:
  // 重新设置保活定时器下次超时时间
	inet_csk_reset_keepalive_timer (sk, elapsed);
	goto out;

death:
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

void tcp_init_xmit_timers(struct sock *sk)
{
	inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer,
				  &tcp_keepalive_timer);
}
EXPORT_SYMBOL(tcp_init_xmit_timers);
