#ifndef _LINUX_SLAB_DEF_H
#define	_LINUX_SLAB_DEF_H

/*
 * Definitions unique to the original Linux SLAB allocator.
 */

struct kmem_cache {
/* 1) Cache tunables. Protected by cache_chain_mutex */
  // 要转移进本地高速缓存或从本地高速缓存中转移出去的对象的数量
	unsigned int batchcount;
  // 本地高速缓存中空闲对象的最大数目
	unsigned int limit;
  // 是否存在CPU共享高速缓存，CPU共享高速缓存指针保存在kmem_cache_node结构中
	unsigned int shared;

  // 对象长度 + 填充字节
	unsigned int size;
  // size的倒数，加快计算
	u32 reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

  // 高速缓存永久属性的标识，如果SLAB描述符放在外部(不放在SLAB中)，则CFLAGS_OFF_SLAB置1
	unsigned int flags;		/* constant flags */
  // 每个SLAB中对象的个数(在同一个高速缓存中slab中对象个数相同)
	unsigned int num;		/* # of objs per slab */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
  // 一个单独SLAB中包含的连续页框数目的对数
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
  // 分配页框时传递给伙伴系统的一组标识
	gfp_t allocflags;

  // SLAB使用的颜色个数
	size_t colour;			/* cache colouring range */
  // SLAB中基本对齐偏移，当新SLAB着色时，偏移量的值需要乘上这个基本对齐偏移量，
  // 理解就是1个偏移量等于多少个B大小的值
	unsigned int colour_off;	/* colour offset */
  // 空闲对象链表放在外部时使用，其指向的SLAB高速缓存来存储空闲对象链表
	struct kmem_cache *freelist_cache;
  // 空闲对象链表的大小
	unsigned int freelist_size;

	/* constructor func */
	void (*ctor)(void *obj);

/* 4) cache creation/removal */
	const char *name;
	struct list_head list;
	int refcount;
  // 高速缓存中对象的大小
	int object_size;
	int align;

/* 5) statistics */
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */
#ifdef CONFIG_MEMCG_KMEM
  // 用于分组资源限制
	struct memcg_cache_params *memcg_params;
#endif

/* 6) per-cpu/per-node data, touched during every alloc/free */
	/*
	 * We put array[] at the end of kmem_cache, because we want to size
	 * this array to nr_cpu_ids slots instead of NR_CPUS
	 * (see kmem_cache_init())
	 * We still use [NR_CPUS] and not [1] or [0] because cache_cache
	 * is statically defined, so we reserve the max number of cpus.
	 *
	 * We also need to guarantee that the list is able to accomodate a
	 * pointer for each node since "nodelists" uses the remainder of
	 * available pointers.
	 */
  // 结点链表，此高速缓存可能在不同NUMA的结点都有SLAB链表
	struct kmem_cache_node **node;
  // 指向包含空闲对象的本地高速缓存，每个CPU有一个该结构，当有对象释放时，优先放入本地CPU高速缓存中
	struct array_cache *array[NR_CPUS + MAX_NUMNODES];
	/*
	 * Do not add fields after array[]
	 */
};

#endif	/* _LINUX_SLAB_DEF_H */
