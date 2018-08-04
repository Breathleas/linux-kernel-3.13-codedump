/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock 
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _REQUEST_SOCK_H
#define _REQUEST_SOCK_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/bug.h>

#include <net/sock.h>

struct request_sock;
struct sk_buff;
struct dst_entry;
struct proto;

// TCP中，指向tcp_request_sock_ops结构体
struct request_sock_ops {
	int		family;
  // obj_size为具体结构体的大小，TCP中就是tcp_request_sock_ops结构体的大小
	int		obj_size;
	struct kmem_cache	*slab;
	char		*slab_name;
  // 发送SYN+ACK段的指针
	int		(*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req);
  // 发送ACK段的指针
	void		(*send_ack)(struct sock *sk, struct sk_buff *skb,
				    struct request_sock *req);
  // 发送RST段的指针
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb);
  // 析构函数，在释放连接请求块时被调用，用来清理释放资源。
	void		(*destructor)(struct request_sock *req);
	void		(*syn_ack_timeout)(struct sock *sk,
					   struct request_sock *req);
};

int inet_rtx_syn_ack(struct sock *parent, struct request_sock *req);

/* struct request_sock - mini sock to represent a connection request
 */
// 该结构用于描述对端的MSS、本端的接收窗口大小以及控制连接操作的信息，如超时时间等。
struct request_sock {
	struct sock_common		__req_common;
	struct request_sock		*dl_next;
  // 客户端连接请求段中通告的MSS。如果无通告，则为初始值，即RFC中建议的536。
	u16				mss;
  // 发送SYN+ACK的次数，超过系统上限时取消连接操作。
	u8				num_retrans; /* number of retransmits */
	u8				cookie_ts:1; /* syncookie: encode tcpopts in timestamp */
	u8				num_timeout:7; /* number of timeouts */
	/* The following two fields can be easily recomputed I think -AK */
  // 标识本端的最大通知窗口，在生成SYN+ACK段时计算该值。
	u32				window_clamp; /* window clamp at creation time */
  // 标识在连接建立时本端接收窗口大小，初始化为0，在生成SYN+ACK段时计算该值
	u32				rcv_wnd;	  /* rcv_wnd offered first time */
  // 下一个将要发送的ACK中的时间戳值。当一个包含最后发送ACK确认序号的段到达时，
  // 该段中的时间戳被保存在ts_recent中。
	u32				ts_recent;

  // 服务端接收到连接请求，并发送SYN+ACK段做为应答后，等待客户端确认的超时时间。
  // 一旦超时，会重新发送SYN+ACK段，直到连接建立或重发次数达到上限。
	unsigned long			expires;
  // 处理连接请求的函数指针表，TCP中指向tcp_request_sock_ops
	const struct request_sock_ops	*rsk_ops;
  // 指向对于状态的传输控制块，在连接建立前无效，三次握手后会创建对应的传输控制块。
  // 而此时连接请求块也完成了历史使命，调用accept将该连接请求快取走并释放。
	struct sock			*sk;
	u32				secid;
	u32				peer_secid;
};

static inline struct request_sock *reqsk_alloc(const struct request_sock_ops *ops)
{
	struct request_sock *req = kmem_cache_alloc(ops->slab, GFP_ATOMIC);

	if (req != NULL)
		req->rsk_ops = ops;

	return req;
}

static inline void __reqsk_free(struct request_sock *req)
{
	kmem_cache_free(req->rsk_ops->slab, req);
}

static inline void reqsk_free(struct request_sock *req)
{
	req->rsk_ops->destructor(req);
	__reqsk_free(req);
}

extern int sysctl_max_syn_backlog;

/** struct listen_sock - listen state
 *
 * @max_qlen_log - log_2 of maximal queued SYNs/REQUESTs
 */
// 用来存储连接请求块。该结构的实例在listen系统调用之后才会被创建。
struct listen_sock {
  // 实际分配用来保存SYN请求连接的request_sock结构数组的长度，其值为
  // nr_table_entries以2为底的对数
	u8			max_qlen_log;
	u8			synflood_warned;
	/* 2 bytes hole, try to use */
  // 当前连接请求块数目
	int			qlen;
  // 当前未重传过SYN+ACK段的请求块数目。如果每次建立连接都顺利，三次握手的段都没有重传，
  // 那么qlen_young=qlen，有SYN+ACK段重传时会递减。
	int			qlen_young;
  // 用来记录连接建立定时器处理函数下次被激活时需要处理的连接请求块散列表入口。
  // 在本次处理结束时讲当前的入口保存到该字段中，在下次处理时就从该入口开始处理。
	int			clock_hand;
  // 用来计算SYN请求块散列表键值的随机数
	u32			hash_rnd;
  // 实际分配用来保存SYN请求连接的request_sock结构数组的长度
	u32			nr_table_entries;
  // 指向request_sock结构散列表，在listen系统调用中生成。
	struct request_sock	*syn_table[0];
};

/*
 * For a TCP Fast Open listener -
 *	lock - protects the access to all the reqsk, which is co-owned by
 *		the listener and the child socket.
 *	qlen - pending TFO requests (still in TCP_SYN_RECV).
 *	max_qlen - max TFO reqs allowed before TFO is disabled.
 *
 *	XXX (TFO) - ideally these fields can be made as part of "listen_sock"
 *	structure above. But there is some implementation difficulty due to
 *	listen_sock being part of request_sock_queue hence will be freed when
 *	a listener is stopped. But TFO related fields may continue to be
 *	accessed even after a listener is closed, until its sk_refcnt drops
 *	to 0 implying no more outstanding TFO reqs. One solution is to keep
 *	listen_opt around until	sk_refcnt drops to 0. But there is some other
 *	complexity that needs to be resolved. E.g., a listener can be disabled
 *	temporarily through shutdown()->tcp_disconnect(), and re-enabled later.
 */
struct fastopen_queue {
	struct request_sock	*rskq_rst_head; /* Keep track of past TFO */
	struct request_sock	*rskq_rst_tail; /* requests that caused RST.
						 * This is part of the defense
						 * against spoofing attack.
						 */
	spinlock_t	lock;
	int		qlen;		/* # of pending (TCP_SYN_RECV) reqs */
	int		max_qlen;	/* != 0 iff TFO is currently enabled */
};

/** struct request_sock_queue - queue of request_socks
 *
 * @rskq_accept_head - FIFO head of established children
 * @rskq_accept_tail - FIFO tail of established children
 * @rskq_defer_accept - User waits for some data after accept()
 * @syn_wait_lock - serializer
 *
 * %syn_wait_lock is necessary only to avoid proc interface having to grab the main
 * lock sock while browsing the listening hash (otherwise it's deadlock prone).
 *
 * This lock is acquired in read mode only from listening_get_next() seq_file
 * op and it's acquired in write mode _only_ from code that is actively
 * changing rskq_accept_head. All readers that are holding the master sock lock
 * don't need to grab this lock in read mode too as rskq_accept_head. writes
 * are always protected from the main sock lock.
 */
struct request_sock_queue {
	struct request_sock	*rskq_accept_head;
	struct request_sock	*rskq_accept_tail;
	rwlock_t		syn_wait_lock;
	u8			rskq_defer_accept;
	/* 3 bytes hole, try to pack */
	struct listen_sock	*listen_opt;
	struct fastopen_queue	*fastopenq; /* This is non-NULL iff TFO has been
					     * enabled on this listener. Check
					     * max_qlen != 0 in fastopen_queue
					     * to determine if TFO is enabled
					     * right at this moment.
					     */
};

int reqsk_queue_alloc(struct request_sock_queue *queue,
		      unsigned int nr_table_entries);

void __reqsk_queue_destroy(struct request_sock_queue *queue);
void reqsk_queue_destroy(struct request_sock_queue *queue);
void reqsk_fastopen_remove(struct sock *sk, struct request_sock *req,
			   bool reset);

static inline struct request_sock *
	reqsk_queue_yank_acceptq(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	queue->rskq_accept_head = NULL;
	return req;
}

static inline int reqsk_queue_empty(struct request_sock_queue *queue)
{
	return queue->rskq_accept_head == NULL;
}

static inline void reqsk_queue_unlink(struct request_sock_queue *queue,
				      struct request_sock *req,
				      struct request_sock **prev_req)
{
	write_lock(&queue->syn_wait_lock);
	*prev_req = req->dl_next;
	write_unlock(&queue->syn_wait_lock);
}

static inline void reqsk_queue_add(struct request_sock_queue *queue,
				   struct request_sock *req,
				   struct sock *parent,
				   struct sock *child)
{
	req->sk = child;
	sk_acceptq_added(parent);

	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_head = req;
	else
		queue->rskq_accept_tail->dl_next = req;

	queue->rskq_accept_tail = req;
	req->dl_next = NULL;
}

static inline struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	WARN_ON(req == NULL);

	queue->rskq_accept_head = req->dl_next;
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_tail = NULL;

	return req;
}

static inline int reqsk_queue_removed(struct request_sock_queue *queue,
				      struct request_sock *req)
{
	struct listen_sock *lopt = queue->listen_opt;

	if (req->num_timeout == 0)
		--lopt->qlen_young;

	return --lopt->qlen;
}

static inline int reqsk_queue_added(struct request_sock_queue *queue)
{
	struct listen_sock *lopt = queue->listen_opt;
	const int prev_qlen = lopt->qlen;

	lopt->qlen_young++;
	lopt->qlen++;
	return prev_qlen;
}

static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return queue->listen_opt != NULL ? queue->listen_opt->qlen : 0;
}

static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen_young;
}

static inline int reqsk_queue_is_full(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen >> queue->listen_opt->max_qlen_log;
}

static inline void reqsk_queue_hash_req(struct request_sock_queue *queue,
					u32 hash, struct request_sock *req,
					unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->expires = jiffies + timeout;
	req->num_retrans = 0;
	req->num_timeout = 0;
	req->sk = NULL;
	req->dl_next = lopt->syn_table[hash];

	write_lock(&queue->syn_wait_lock);
	lopt->syn_table[hash] = req;
	write_unlock(&queue->syn_wait_lock);
}

#endif /* _REQUEST_SOCK_H */
