

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

#include <asm/pgtable.h>
#include <asm/pgtable_types.h>

#include <linux/err.h>
#include <linux/time.h>

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h>

#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/net_namespace.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/sock.h>

#include <linux/sysctl.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

// #define TOA_USE_MULTI_HOOK 
#ifdef TOA_USE_MULTI_HOOK
#include <multi_hook.h>
#endif



//  toa stats ------------------------------------

const char toa_version[] = "3.0.1";

enum
{
    STATS_V4_ESTABLISH = 0,
    STATS_IPV4_OPTION,
    STATS_TCPV4_OPTION,
    STATS_V4_SAVED,
    STATS_V6_ESTABLISH,
    STATS_IPV6_OPTION,
    STATS_V6_SAVED,

    STATS_GET_V4,
    STATS_GET_V4_SUCC,
    STATS_GET_V6,
    STATS_GET_V6_SUCC,

    STATS_MAX,
};

struct toa_stats
{
    __u64 stats[STATS_MAX];
};

struct toa_stats __percpu * toa_stats_cpu;


// the uoa_cpu_stats only be added in the local cpu and can be read from other cpu
static inline void toa_stats_inc(int index)
{
    struct toa_stats* s = this_cpu_ptr(toa_stats_cpu);
    s->stats[index]++;
}

static void toa_map_show(struct seq_file *seq);

static int toa_stats_show(struct seq_file *seq, void *arg)
{
    struct toa_stats global_stats;
    int i, j;

    seq_printf(seq, "toa version: %s\n", toa_version);
    seq_puts(seq, "CPU      V4_ESTB   IPV4_OPT  TCPV4_OPT  V4_SAVED  V6_ESTB  IPV6_OPT  V6_SAVED  ");
    seq_puts(seq, "GET_V4  GET_V4_SUCC GET_V6  GET_V6_SUCC\n");
    
    memset(&global_stats, 0, sizeof(global_stats));
    for_each_possible_cpu(i) 
    {
        struct toa_stats *s = per_cpu_ptr(toa_stats_cpu, i);
        __u64 tmp;

        seq_printf(seq, "%3d:  ", i);
        for (j = 0; j < STATS_MAX; j++)
        {   tmp = s->stats[j];
            global_stats.stats[j] += tmp;
            seq_printf(seq, "%8llu  ", tmp);
        }
        seq_printf(seq, "\n");
    }

    seq_printf(seq, "total:");
    for (j = 0; j < STATS_MAX; j++)
        seq_printf(seq, "%8llu  ", global_stats.stats[j]);
    seq_printf(seq, "\n");

    toa_map_show(seq);

    return 0;
}

static int toa_stats_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, toa_stats_show, NULL);
}

static const struct file_operations toa_stats_fops = 
{
    .owner      = THIS_MODULE,
    .open       = toa_stats_seq_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

static int toa_stats_init(void)
{
    int i;

    toa_stats_cpu = alloc_percpu(struct toa_stats);
    if  (!toa_stats_cpu)
    {   pr_warn("%s: toa_stats_cpu failed\n", __func__);
        return -ENOMEM;
    }

    for_each_possible_cpu(i)
    {
        struct toa_stats* s = per_cpu_ptr(toa_stats_cpu, i);
        memset(s, 0, sizeof(*s));
    }

    proc_create("toa_stats", 0, init_net.proc_net, &toa_stats_fops);

    return 0;
}

static void toa_stats_exit(void)
{
    remove_proc_entry("toa_stats", init_net.proc_net);
    free_percpu(toa_stats_cpu);
}



// toa_map ----------------------------------------------------------------------------------------------

union two_addr{
    struct{
        unsigned char saddr[4];
        unsigned char daddr[4];
    }ipv4;
    struct{
        unsigned char saddr[16];
        unsigned char daddr[16];
    }ipv6;
};

struct four_tuple{
    unsigned int type; // indicate this is ipv4 or ipv6 addresses;
    __be16 sport, dport;
    union two_addr addrs;
};


static inline void four_tuple_display(const char* prefix, const struct four_tuple* tuple)
{
#ifdef DEBUG  
    if  (tuple->type == 0)
    {
        pr_debug("%s %pI4:%d -> %pI4:%d\n", prefix, 
               tuple->addrs.ipv4.saddr, ntohs(tuple->sport),
                tuple->addrs.ipv4.daddr, ntohs(tuple->dport));
    }
    else
    {
        pr_debug("%s %pI6:%d -> %pI6:%d\n", prefix, 
                tuple->addrs.ipv6.saddr, ntohs(tuple->sport),
                tuple->addrs.ipv6.daddr, ntohs(tuple->dport));
    }
#endif
}


struct toa_map_bucket
{
    struct hlist_head head;
    spinlock_t       lock;
    long long num;
};

// the address of sk is the master key
struct toa_map_entry
{
    struct hlist_node hlist;
    
    struct sock *sk;  // also key
    struct four_tuple value;
};


static int toa_map_table_bits = 12;
module_param_named(toa_map_table_bits, toa_map_table_bits, int, 0444);
MODULE_PARM_DESC(toa_map_table_bits, "TOA mapping table hash bits");

static int toa_map_table_size  __read_mostly;
static int toa_map_table_mask  __read_mostly;


static struct toa_map_bucket* toa_map_table __read_mostly;
static struct kmem_cache *toa_map_cache __read_mostly;

static void toa_map_show(struct seq_file *seq)
{
    long long total = 0;
    long long max_num = 0, min_num = 0xffffffff;
    unsigned i;

    for (i = 0; i < toa_map_table_size; i++)
    {
        long long x =  toa_map_table[i].num;
        total += x;
        if  (x > max_num)  max_num = x;
        if  (x < min_num)  min_num = x;
    }

    seq_printf(seq, "toa_map: total_num: %lld buckets: %d avg_num: %lld max_num: %lld min_num: %lld\n",
            total, toa_map_table_size, total / toa_map_table_size, max_num, min_num);

}

static unsigned long toa_sock_hash(struct sock* sk)
{
    unsigned long src = (unsigned long)sk;
    unsigned ans = src;
    ans ^= src >> 8;
    ans ^= src >> 16;
    ans ^= src >> 24;
    return ans & toa_map_table_mask;
}

static void toa_map_insert(struct toa_map_entry* entry)
{
    int index = toa_sock_hash(entry->sk);
    struct toa_map_bucket* bucket = toa_map_table + index;
    struct hlist_head* head = &bucket->head;

    spin_lock_bh(&bucket->lock);

    hlist_add_head_rcu(&entry->hlist, head);
    bucket->num++;

    spin_unlock_bh(&bucket->lock);
}

static bool toa_map_get(struct sock* sk, struct four_tuple* value)
{
    int index = toa_sock_hash(sk);
    struct toa_map_bucket* bucket = toa_map_table + index;
    struct hlist_head* head = &bucket->head;
    struct toa_map_entry* entry;
    bool retval = false;

    spin_lock_bh(&bucket->lock);

    hlist_for_each_entry_rcu(entry, head, hlist)
    {
        if  (entry->sk == sk)
        {   memcpy(value, &entry->value, sizeof(*value));
            retval = true;
            break;
        }
    }

    spin_unlock_bh(&bucket->lock);
    
    return retval;
}

// static void toa_map_remove(struct toa_map_entry* entry)
static void toa_map_remove(struct sock* sk)
{
    int index = toa_sock_hash(sk);
    struct toa_map_bucket* bucket = toa_map_table + index;
    struct hlist_head* head = &bucket->head;
    struct toa_map_entry* entry;
    struct hlist_node* node;


    spin_lock_bh(&bucket->lock);

    hlist_for_each_entry_safe(entry, node, head, hlist)
    {
        if  (entry->sk == sk)
        {
            hlist_del_rcu(&entry->hlist);
            entry->sk->sk_destruct = inet_sock_destruct;
            kmem_cache_free(toa_map_cache, entry);
            bucket->num--;

            break;
        }
    }

    spin_unlock_bh(&bucket->lock);
}


static void tcp_sk_destruct_toa(struct sock* sk);

static void toa_map_flush(void)
{
    int i;
    int count = 0;


    for (i = 0; i < toa_map_table_size; i++)
    {
        struct toa_map_bucket* bucket = toa_map_table + i;
        struct hlist_head* head = &bucket->head;
        struct hlist_node* node;
        struct toa_map_entry* entry;

        spin_lock_bh(&bucket->lock);

        hlist_for_each_entry_safe(entry, node, head, hlist)
        {
            struct sock* sk = entry->sk;
            count++;

            hlist_del_rcu(&entry->hlist);
            bucket->num--;

            if  (sk && (sk->sk_destruct == tcp_sk_destruct_toa))
                sk->sk_destruct = inet_sock_destruct;
            
            kmem_cache_free(toa_map_cache, entry);
        }

        spin_unlock_bh(&bucket->lock);
    }
    
    pr_info("%s: flush %d\n", __func__, count);
}

static int toa_map_init(void)
{
    int i;

    toa_map_table_size = 1 << toa_map_table_bits;
    toa_map_table_mask = toa_map_table_size - 1;

    toa_map_table = vmalloc(sizeof(struct toa_map_bucket) * toa_map_table_size);
    if  (!toa_map_table)
    {   pr_warn("fail to create uoa_map_table\n");
        return -ENOMEM;
    }
    
    for (i = 0; i < toa_map_table_size; i++)
    {
        INIT_HLIST_HEAD(&toa_map_table[i].head);
        spin_lock_init(&toa_map_table[i].lock);
        toa_map_table[i].num = 0;
    }

    toa_map_cache = kmem_cache_create("toa_map", 
        sizeof(struct toa_map_entry), 0, SLAB_HWCACHE_ALIGN, NULL);
    if  (!toa_map_cache)
    {   pr_warn("fail to create uoa_map_cache\n");
        return -ENOMEM;
    }

    return 0;
}

static void toa_map_exit(void)
{
    toa_map_flush();
    kmem_cache_destroy(toa_map_cache);
    
    synchronize_net();
}


// inet_getname -------------------------------------------------------------------------------------------

unsigned long sk_data_ready_addr = 0;

static int vip_enable = 1;
module_param_named(vip_enable, vip_enable, int, 0444);
MODULE_PARM_DESC(vip_enable, "disable TTGW VIP and virtul port info by setting it to 0");

static int v6_to_v4_enable = 0;
module_param_named(v6_to_v4_enable, v6_to_v4_enable, int, 0444);
MODULE_PARM_DESC(v6_to_v4_enable, "enable specific ipv6 addr trans to ipv4 addr, \
determined by v6_to_v4_prefix_str's first 96 bits");

static char* v6_to_v4_prefix_str = NULL;
module_param_named(v6_to_v4_prefix_str, v6_to_v4_prefix_str, charp, 0444);
MODULE_PARM_DESC(v6_to_v4_prefix_str, "the first 96 bits as prefix \
to determine wheather trans an ipv6 addr to ipv4 addr");

static char* v6_to_v4_prefix_str_default = "64:ff9b::";
static u8 v6_to_v4_prefix_addr[16]; // the first 96 bit as prefix to determine v6 to v4;



static int toa_ipv6_addr_assign(__be16 port, u8* addr, struct sockaddr* uaddr)
{
    if  (unlikely(v6_to_v4_enable == 1 && strncmp(addr, v6_to_v4_prefix_addr, 12) == 0))
    {   // trans v6 to v4;
        struct sockaddr_in* sin = (struct sockaddr_in*)uaddr;
        sin->sin_addr.s_addr = *(unsigned*)(addr + 12);
        sin->sin_port = port;
        sin->sin_family = AF_INET;
        return sizeof(*sin);
    }
    else
    {
        struct sockaddr_in6* sin = (struct sockaddr_in6*)uaddr;
        memcpy(&sin->sin6_addr, addr, 16);
        sin->sin6_port = port;
        sin->sin6_family = AF_INET6;
        return sizeof(*sin);
    }
} 


static int four_tuple_to_sockaddr_new(struct four_tuple* value, struct sockaddr* uaddr, int* len_p, bool peer)
{
    int ret = -1;

    // ipv4
    if  (value->type == 0)
    {   
        struct sockaddr_in* sin = (struct sockaddr_in*)uaddr;

        if  (peer)
        {   if  (value->sport)
            {   sin->sin_addr.s_addr = *(unsigned*)value->addrs.ipv4.saddr;
                sin->sin_port = value->sport;
                sin->sin_family = AF_INET;
                *len_p = sizeof(*sin);
                ret = 0;
            }
        }
        else
        {   if  (value->dport)
            {   sin->sin_addr.s_addr = *(unsigned*)value->addrs.ipv4.daddr;
                sin->sin_port = value->dport;
                sin->sin_family = AF_INET;
                *len_p = sizeof(*sin);
                ret = 0;
            }
        }
    }
    // ipv6
    else if  (value->type == 1)
    {
        if  (peer)
        {   if  (value->sport)
            {   
                *len_p = toa_ipv6_addr_assign(value->sport, value->addrs.ipv6.saddr, uaddr);
                ret = 0;
            }
        }
        else
        {   if  (value->dport)
            {   
                *len_p = toa_ipv6_addr_assign(value->dport, value->addrs.ipv6.daddr, uaddr);
                ret = 0;
            }
        }
    }

    return ret;
}

static int inet_getname_with_toa(struct socket* sock, int af_inet, struct sockaddr* uaddr, int* len_p, int peer)
{
    struct sock* sk = sock->sk;
    bool found = false;
    struct four_tuple value;

    if  (unlikely(vip_enable== 0 && peer == 0))
        return -1;

    found = toa_map_get(sk, &value);

    if  (found)
    {
        four_tuple_display(peer? "inet_getname_with_toa peer:  " : "inet_getname_with_toa local: ", &value);

        return four_tuple_to_sockaddr_new(&value, uaddr, len_p, peer);
    }

    return -1;
}



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)

typedef int (*inet_getname_t)(struct socket *sock, struct sockaddr *uaddr, int peer);

inet_getname_t inet_getname_prev;
inet_getname_t inet6_getname_prev;

// static int inet_getname_toa_in_multi_hook(struct socket *sock, struct sockaddr *uaddr,int peer)
// {
//     pr_debug("inet_getname_toa_in_multi_hook\n");
//     return inet_getname_prev(sock, uaddr, peer);
//     // return 0;
// }


static int inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,int peer)
{
    int retval = 0;
    int new_len = 0;
    toa_stats_inc(STATS_GET_V4);
    // pr_debug("inet_getname_toa\n");

    retval = inet_getname_prev(sock, uaddr, peer);
    if  (retval < 0)  return retval;

    if  (inet_getname_with_toa(sock, AF_INET, uaddr, &new_len, peer) == 0)
    {   retval = new_len;
        toa_stats_inc(STATS_GET_V4_SUCC);
    }

    return retval;
}

static int inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr, int peer)
{
    int retval = 0;
    int new_len = 0;
    toa_stats_inc(STATS_GET_V6);

    retval = inet6_getname_prev(sock, uaddr, peer);
    if  (retval < 0)  return retval;


    if  (inet_getname_with_toa(sock, AF_INET6, uaddr, &new_len, peer) == 0)
    {   retval = new_len;
        toa_stats_inc(STATS_GET_V6_SUCC);
    }

    return retval;
}


#else


typedef int (*inet_getname_t)(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer);

inet_getname_t inet_getname_prev;
inet_getname_t inet6_getname_prev;

static int inet_getname_toa(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer)
{
    int retval = 0;
    int new_len = 0;
    toa_stats_inc(STATS_GET_V4);

    retval = inet_getname_prev(sock, uaddr, uaddr_len, peer);
    if  (retval < 0)  return retval;

    if  (inet_getname_with_toa(sock, AF_INET, uaddr, &new_len, peer) == 0)
    {   
        *uaddr_len = new_len;
        toa_stats_inc(STATS_GET_V4_SUCC);
    }

    return retval;
}

static int inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer)
{
    int retval = 0;
    int new_len = 0;
    toa_stats_inc(STATS_GET_V6);

    retval = inet6_getname_prev(sock, uaddr, uaddr_len, peer);
    if  (retval < 0)  return retval;

    if  (inet_getname_with_toa(sock, AF_INET6, uaddr, &new_len, peer) == 0)
    {   
        *uaddr_len = new_len;
        toa_stats_inc(STATS_GET_V6_SUCC);
    }

    return retval;
}

#endif


// tcp_hook -------------------------------------------------------------------------------------------


struct ip_option{
    union{
        struct{
            __u8 type;
            __u8 length;
            __u8 operation;
            __u8 padding;
        }ipv4;
        struct{
            __u8 nexthdr;
            __u8 hdrlen;
            __u8 option;
            __u8 optlen;
        }ipv6;
    }header;
    
    __be16 sport, dport;
    
    union two_addr addrs;
};

#define IPV4_OPTION_TYPE 31
#define IPV4_OPTION_ASYM_TYPE 30
#define IPV6_HEADER_OPTION 31
#define IPV6_HEADER_ASYM_OPTION 30

#define IP_OPTION_IPV4_LEN  16
#define IP_OPTION_IPV6_LEN  40

#define IPV6_HEADER_IPV4_LEN ((IP_OPTION_IPV4_LEN) / 8 - 1)
#define IPV6_HEADER_IPV6_LEN ((IP_OPTION_IPV6_LEN) / 8 - 1)
#define IPV6_HEADER_OPTION_IPV4_LEN (IP_OPTION_IPV4_LEN - 4)
#define IPV6_HEADER_OPTION_IPV6_LEN (IP_OPTION_IPV6_LEN - 4)


static void tcp_ip_to_four_tuple(int type, void* ip, struct tcphdr* tcph, struct four_tuple* outside)
{

    outside->type = type;
    outside->sport = tcph->source;
    outside->dport = tcph->dest;
    memset(&outside->addrs, 0, sizeof(outside->addrs));

    if  (type == 0)
    {   struct iphdr* iph = ip;
        *(unsigned*)outside->addrs.ipv4.saddr = iph->saddr;
        *(unsigned*)outside->addrs.ipv4.daddr = iph->daddr;
    }
    else if  (type == 1)
    {   struct ipv6hdr* ip6h = ip;
        memcpy(outside->addrs.ipv6.saddr, &ip6h->saddr, 16);
        memcpy(outside->addrs.ipv6.daddr, &ip6h->daddr, 16);
    }
}

static void tcp_ip_display(const char* prefix, int type, void* ip, struct tcphdr* tcph)
{
    struct four_tuple outside;
    tcp_ip_to_four_tuple(type, ip, tcph, &outside);
    four_tuple_display(prefix, &outside);
}


static void tcp_sk_destruct_toa(struct sock* sk)
{
    toa_map_remove(sk);
    inet_sock_destruct(sk);
}


static int ip_option_to_four_tuple(int outside, struct ip_option* src, struct four_tuple* dst)
{
    int inside = -1;
    
    if  (outside == 0){
        inside = src->header.ipv4.operation;
    }
    else if  (outside == 1){
        if  (src->header.ipv6.optlen == IPV6_HEADER_OPTION_IPV4_LEN)
            inside = 0;
        else if  (src->header.ipv6.optlen == IPV6_HEADER_OPTION_IPV6_LEN)
            inside = 1;
    }

    if  (inside == 0){
        memset(dst, 0, sizeof(struct four_tuple));
        memcpy(dst, src, IP_OPTION_IPV4_LEN);
        dst->type = 0;

        return IP_OPTION_IPV4_LEN;
    }
    else if  (inside == 1){
        memcpy(dst, src, IP_OPTION_IPV6_LEN);
        dst->type = 1;

        return IP_OPTION_IPV6_LEN;
    }

    return -1;
}


// linux-5.4.56-bm  has introduced this content.

#define TCPOPT_TOA__         254


/* MUST be 4n !!!! */
#define TCPOLEN_TOA_IP4__        8		/* |opcode|size|ip+port| = 1 + 1 + 6 */
#define TCPOLEN_TOA_IP4_EXTRA__ 16        /* 1 + 1 + 6 + 2 + 6 */
#define TCPOLEN_TOA_IP6__       20		/* |opcode|size|ip_of_v6+port| = 1 + 1 + 18 */

/* MUST be 4 bytes alignment */
struct toa_ip4_data__ {
    __u8 opcode;
    __u8 opsize;
    __u16 port;
    __u32 ip;
};

struct toa_ip4_extra_data__ {
    struct toa_ip4_data__ legacy_data;
    __u8  padding[2];
    __u16 dst_port;
    __u32 dst_ip;
};

struct  toa_ip6_data__ {
    __u8 opcode;
    __u8 opsize;
    __u16 port;
    struct in6_addr in6_addr;
};


static struct toa_map_entry* toa_parse_tcp_option(struct sk_buff* skb, int ip_type, void* iph, struct tcphdr* tcph)
{
    const unsigned char *ptr= (const unsigned char *)(tcph + 1);
    int length = (tcph->doff * 4) - sizeof(struct tcphdr);
    const char* start = NULL;
    struct toa_map_entry* entry = NULL;


    while (length > 0) {
        int opcode = *ptr++;
        int opsize;

        switch (opcode) {
        case TCPOPT_EOL:
            return NULL;
        case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
            length--;
            continue;
        default:
            if (length < 2)
                return NULL;
            opsize = *ptr++;
            if (opsize < 2) /* "silly options" */
                return NULL;
            if (opsize > length)
                return NULL;	/* don't parse partial options */
            
            switch (opcode) {

            case TCPOPT_TOA__:
                start = ptr - 2;
                
                pr_debug("toa_parse_tcp_option: 2, opcode: %d, opsize: %d\n", opcode, opsize);
                tcp_ip_display("toa_parse_tcp_option:     outside: ", ip_type, iph, tcph);

                if  (opsize == TCPOLEN_TOA_IP4__ || opsize == TCPOLEN_TOA_IP4_EXTRA__)
                {
                    struct toa_ip4_extra_data__* option = (struct toa_ip4_extra_data__*)start;
                    toa_stats_inc(STATS_TCPV4_OPTION);

                    entry = kmem_cache_alloc(toa_map_cache, GFP_ATOMIC);
                    if  (!entry)
                    {   pr_warn("can not alloc entry\n");
                        return NULL;
                    }
                    memset(entry, 0, sizeof(*entry));

                    entry->value.sport = option->legacy_data.port;
                    *(unsigned*)entry->value.addrs.ipv4.saddr = option->legacy_data.ip;

                    if  (opsize == TCPOLEN_TOA_IP4_EXTRA__)
                    {   entry->value.dport = option->dst_port;
                        *(unsigned*)entry->value.addrs.ipv4.daddr = option->dst_ip;
                        // pr_debug("toa_parse_tcp_option: opt: %pI4:%d, value: %pI4:%d",
                        //         &option->dst_ip, ntohs(option->dst_port),
                        //         entry->value.addrs.ipv4.daddr, ntohs(entry->value.dport));
                    }

                }
                else if  (opsize == TCPOLEN_TOA_IP6__)
                {
                    struct toa_ip6_data__* option = (struct toa_ip6_data__*)start;

                    entry = kmem_cache_alloc(toa_map_cache, GFP_ATOMIC);
                    if  (!entry)
                    {   pr_warn("can not alloc entry\n");
                        return NULL;
                    }
                    memset(entry, 0, sizeof(*entry));

                    entry->value.type = 1; // ipv6
                    entry->value.sport = option->port;
                    memcpy(entry->value.addrs.ipv6.saddr, &option->in6_addr, 16);

                }
                else
                    pr_warn("get toa option with illegal length: %d\n", opsize);

                return entry;
            }
            ptr += opsize-2;
            length -= opsize;
        }
    }

    return NULL;
}


static int toa_process_v4(struct sock* newsock, struct sk_buff* skb)
{
    struct iphdr* iph = ip_hdr(skb);
    struct tcphdr* tcph = tcp_hdr(skb);
    struct toa_map_entry* entry = NULL;

    if  (iph->ihl > 5 
        && iph->protocol == IPPROTO_TCP
        && (((struct ip_option*)(iph + 1))->header.ipv4.type == IPV4_OPTION_TYPE
            || ((struct ip_option*)(iph + 1))->header.ipv4.type == IPV4_OPTION_ASYM_TYPE)
        )
    {
        struct ip_option* ipopt = (struct ip_option*)(iph + 1);

        toa_stats_inc(STATS_IPV4_OPTION);
        tcp_ip_display("toa_process_v4: outside: ", 0, iph, tcph);

        entry = kmem_cache_alloc(toa_map_cache, GFP_ATOMIC);
        if  (!entry)
        {   pr_warn("can not alloc entry\n");
            // return newsock;
            return -1;
        }

        ip_option_to_four_tuple(0, ipopt, &entry->value);
        // four_tuple_display("inside:  ", &entry->value);
    }

    // pr_debug("tcph->doff: %d\n", tcph->doff);
    if  (entry == NULL 
            && tcph->doff > 5)
    {
        // tcp_ip_display("outside: ", 0, iph, tcph);

        entry = toa_parse_tcp_option(skb, 0, iph, tcph);		    
    }

    if  (entry)
    {
        four_tuple_display("toa_process_v4:  inside: ", &entry->value);

        entry->sk = newsock;
        newsock->sk_destruct = tcp_sk_destruct_toa;

        toa_map_insert(entry);
        toa_stats_inc(STATS_V4_SAVED);
    }

    return 0;
}



static int toa_process_v6(struct sock* newsock, struct sk_buff* skb)
{
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    struct tcphdr* tcph = tcp_hdr(skb);
    struct toa_map_entry* entry = NULL;


    if  (ip6h->nexthdr == IPPROTO_DSTOPTS
        && ((struct ip_option*)(ip6h +1))->header.ipv6.nexthdr == IPPROTO_TCP
        && (((struct ip_option*)(ip6h +1))->header.ipv6.option == IPV6_HEADER_OPTION
            || ((struct ip_option*)(ip6h +1))->header.ipv6.option == IPV6_HEADER_ASYM_OPTION)
        )
    {
        struct ip_option* ipopt = (struct ip_option*)(ip6h + 1);
        
        toa_stats_inc(STATS_IPV6_OPTION);
        tcp_ip_display("toa_process_v6: outside: ", 1, ip6h, tcph);

        entry = kmem_cache_alloc(toa_map_cache, GFP_ATOMIC);
        if  (!entry)
        {   pr_warn("can not alloc entry\n");
            // return newsock;
            return -1;
        }

        ip_option_to_four_tuple(1, ipopt, &entry->value);
    }

    if  (entry == NULL 
            && tcph->doff > 5)
    {
        // tcp_ip_display("outside: ", 0, iph, tcph);

        entry = toa_parse_tcp_option(skb, 1, ip6h, tcph);		    
    }

    if  (entry)
    {
        four_tuple_display("toa_process_v6:  inside: ", &entry->value);

        entry->sk = newsock;		
        newsock->sk_destruct = tcp_sk_destruct_toa;
        toa_map_insert(entry);
        toa_stats_inc(STATS_V6_SAVED);

    }
    return 0;
}


#ifdef TOA_USE_MULTI_HOOK


// static struct sock* tcp_v4_syn_recv_sock_toa(const struct sock *sk, struct sk_buff *skb,
//         struct request_sock *req, struct dst_entry *dst, struct request_sock *req_unhash, bool *own_req)
static void tcp_v4_syn_recv_sock_toa_in_multi_hook(struct hook_pt_regs* ctx)
{
    struct sock* sk = (struct sock*)ctx->args[0];
    struct sk_buff* skb = (struct sk_buff*)ctx->args[1];
    struct sock* new_sk = (struct sock*)ctx->ret;

    pr_debug("tcp_v4_syn_recv_sock_toa_in_multi_hook, sk: %lx, skb: %lx, ret: %lx\n", 
            (unsigned long)sk, (unsigned long)skb, (unsigned long)new_sk);
    if  (!new_sk)
        return;

    toa_process_v4(new_sk, skb);
}


static void tcp_v6_syn_recv_sock_toa_in_multi_hook(struct hook_pt_regs* ctx)
{
    struct sock* sk = (struct sock*)ctx->args[0];
    struct sk_buff* skb = (struct sk_buff*)ctx->args[1];
    struct sock* new_sk = (struct sock*)ctx->ret;

    pr_debug("tcp_v6_syn_recv_sock_toa_in_multi_hook, sk: %lx, skb: %lx, ret: %lx\n", 
            (unsigned long)sk, (unsigned long)skb, (unsigned long)new_sk);
    if  (!new_sk)
        return;

    toa_process_v6(new_sk, skb);

}

#else
typedef struct sock* (*syn_recv_sock_t)(const struct sock *sk, struct sk_buff *skb,
        struct request_sock *req, struct dst_entry *dst, struct request_sock *req_unhash, bool *own_req);

syn_recv_sock_t tcp_v4_syn_recv_sock_prev;
syn_recv_sock_t tcp_v6_syn_recv_sock_prev;


static struct sock* tcp_v4_syn_recv_sock_toa(const struct sock *sk, struct sk_buff *skb,
        struct request_sock *req, struct dst_entry *dst, struct request_sock *req_unhash, bool *own_req)
{
    struct sock* newsock = tcp_v4_syn_recv_sock_prev(sk, skb, req, dst, req_unhash, own_req);
    if  (!newsock)  return newsock;
    toa_stats_inc(STATS_V4_ESTABLISH);

    toa_process_v4(newsock, skb);

    return newsock;
}


static struct sock *tcp_v6_syn_recv_sock_toa(const struct sock *sk, struct sk_buff *skb,
        struct request_sock *req, struct dst_entry *dst, struct request_sock *req_unhash, bool *own_req)
{    
    struct sock*  newsock = tcp_v6_syn_recv_sock_prev(sk, skb, req, dst, req_unhash, own_req);
    if  (!newsock)  return newsock;
    toa_stats_inc(STATS_V6_ESTABLISH);

    toa_process_v6(newsock, skb);

    return newsock;
}
#endif


// toa hook init -----------------------------------------------------------------------


static unsigned long syn_recv_sock_v4_p = 0;
static unsigned long syn_recv_sock_v6_p = 0;
static unsigned long inet_getname_v4_p = 0;
static unsigned long inet_getname_v6_p = 0;


static int toa_hook_init_addr(void)
{
    struct inet_connection_sock_af_ops* ipv4_specific_p;
    struct inet_connection_sock_af_ops* ipv6_specific_p;
    struct proto_ops* inet_stream_ops_p;
    struct proto_ops* inet6_stream_ops_p;

     
    ipv4_specific_p = (struct inet_connection_sock_af_ops *)kallsyms_lookup_name("ipv4_specific");
    if (!ipv4_specific_p) {
        pr_warn("not found ipv4_specific");
        return -1;
    }

    ipv6_specific_p = (struct inet_connection_sock_af_ops *)kallsyms_lookup_name("ipv6_specific");
    if  (!ipv6_specific_p)
    {   pr_warn("not found ipv6_specific");
        return -1;
    }

    inet_stream_ops_p = (struct proto_ops*)kallsyms_lookup_name("inet_stream_ops");
    if  (!inet_stream_ops_p)
    {   pr_warn("not found inet_stream_ops");
        return -1;
    }

    inet6_stream_ops_p = (struct proto_ops*)kallsyms_lookup_name("inet6_stream_ops");
    if  (!inet6_stream_ops_p)
    {   pr_warn("not found inet6_stream_ops");
        return -1;
    }


    syn_recv_sock_v4_p = (unsigned long)&ipv4_specific_p->syn_recv_sock;
    syn_recv_sock_v6_p = (unsigned long)&ipv6_specific_p->syn_recv_sock;

    inet_getname_v4_p = (unsigned long)&inet_stream_ops_p->getname;
    inet_getname_v6_p = (unsigned long)&inet6_stream_ops_p->getname;

    return 0;
}


#ifdef TOA_USE_MULTI_HOOK

struct hook_ctx_t* syn_recv_sock_v4_hook_ctx = NULL;
struct hook_ctx_t* syn_recv_sock_v6_hook_ctx = NULL;
struct hook_ctx_t* inet_getname_v4_hook_ctx = NULL;
struct hook_ctx_t* inet_getname_v6_hook_ctx = NULL;

static int toa_hook_init_with_multi_hook(void)
{
    int ret = -1;

    syn_recv_sock_v4_hook_ctx = multi_hook_manager_get(syn_recv_sock_v4_p, "syn_recv_sock_v4 inited by toa");
    if  (!syn_recv_sock_v4_hook_ctx)
    {   pr_warn("syn_recv_sock_v4_hook_ctx init failed\n");
        goto err_syn_recv_sock_v4_hook_ctx;
    }

    ret = hook_ctx_register_func(syn_recv_sock_v4_hook_ctx, 1, 1, (unsigned long)tcp_v4_syn_recv_sock_toa_in_multi_hook, 1);
    if  (ret < 0)
    {   pr_warn("tcp_v4_syn_recv_sock_toa init failed\n");
        goto err_syn_recv_sock_v4_func;
    }

    syn_recv_sock_v6_hook_ctx = multi_hook_manager_get(syn_recv_sock_v6_p, "syn_recv_sock_v6 inited by toa");
    if  (!syn_recv_sock_v6_hook_ctx)
    {   pr_warn("syn_recv_sock_v6_hook_ctx init failed\n");
        goto err_syn_recv_sock_v6_hook_ctx;
    }

    ret = hook_ctx_register_func(syn_recv_sock_v6_hook_ctx, 1, 1, (unsigned long)tcp_v6_syn_recv_sock_toa_in_multi_hook, 1);
    if  (ret < 0)
    {   pr_warn("tcp_v6_syn_recv_sock_toa init failed\n");
        goto err_syn_recv_sock_v6_func;
    }


    // inet_getname_prev = (inet_getname_t)*(unsigned long*)inet_getname_v4_p;
    // pr_debug("inet_getname_prev: %lx\n", (unsigned long)inet_getname_prev);

    inet_getname_v4_hook_ctx = multi_hook_manager_get(inet_getname_v4_p, "inet_getname_v4 inited by toa");
    if  (!inet_getname_v4_hook_ctx)
    {   pr_warn("inet_getname_v4_hook_ctx init failed\n");
        goto err_inet_getname_v4_hook_ctx;
    }

    ret = hook_ctx_get_original_func(inet_getname_v4_hook_ctx, (unsigned long*)&inet_getname_prev);
    if  (ret < 0)
    {   pr_warn("get inet_getname_prev failed\n");
        goto err_inet_getname_v4_hook_ctx;
    }
    pr_debug("inet_getname_prev: %lx\n", (unsigned long)inet_getname_prev);

    ret = hook_ctx_register_func(inet_getname_v4_hook_ctx, 0, 5, (unsigned long)inet_getname_toa, 0);
    if  (ret < 0)
    {   pr_warn("inet_getname_toa hook failed\n");
        goto err_inet_getname_v4_func;
    }
    

    // inet6_getname_prev = (inet_getname_t)*(unsigned long*)inet_getname_v6_p;
    // pr_debug("inet6_getname_prev: %lx\n", (unsigned long)inet6_getname_prev);

    inet_getname_v6_hook_ctx = multi_hook_manager_get(inet_getname_v6_p, "inet_getname_v6 inited by toa");
    if  (!inet_getname_v6_hook_ctx)
    {   pr_warn("inet_getname_v6_hook_ctx init failed\n");
        goto err_inet_getname_v6_hook_ctx;
    }

    ret = hook_ctx_get_original_func(inet_getname_v6_hook_ctx, (unsigned long*)&inet6_getname_prev);
    if  (ret < 0)
    {   pr_warn("get inet6_getname_prev failed\n");
        goto err_inet_getname_v6_hook_ctx;
    }
    pr_debug("inet6_getname_prev: %lx\n", (unsigned long)inet6_getname_prev);

    ret = hook_ctx_register_func(inet_getname_v6_hook_ctx, 0, 5, (unsigned long)inet6_getname_toa, 0);
    if  (ret < 0)
    {   pr_warn("inet6_getname_toa hook failed\n");
        goto err_inet_getname_v6_func;
    }

    return 0;    

err_inet_getname_v6_func:
    multi_hook_manager_put(inet_getname_v6_p);
err_inet_getname_v6_hook_ctx:
    hook_ctx_unregister_func(inet_getname_v4_hook_ctx, 0, 5);
err_inet_getname_v4_func:
    multi_hook_manager_put(inet_getname_v4_p);
err_inet_getname_v4_hook_ctx:
    hook_ctx_unregister_func(syn_recv_sock_v6_hook_ctx, 1, 1);
err_syn_recv_sock_v6_func:
    multi_hook_manager_put(syn_recv_sock_v6_p);
err_syn_recv_sock_v6_hook_ctx:
    hook_ctx_unregister_func(syn_recv_sock_v4_hook_ctx, 1, 1);
err_syn_recv_sock_v4_func:
    multi_hook_manager_put(syn_recv_sock_v4_p);
err_syn_recv_sock_v4_hook_ctx:

    return -1;
}

static int toa_hook_init(void)
{
    if  (toa_hook_init_addr() < 0)
        return -1;

    if  (toa_hook_init_with_multi_hook() < 0)
        return -1;

    return 0;
}

static void toa_hook_exit_with_multi_hook(void)
{
    hook_ctx_unregister_func(syn_recv_sock_v4_hook_ctx, 1, 1);
    multi_hook_manager_put(syn_recv_sock_v4_p);

    hook_ctx_unregister_func(syn_recv_sock_v6_hook_ctx, 1, 1);
    multi_hook_manager_put(syn_recv_sock_v6_p);
    
    hook_ctx_unregister_func(inet_getname_v4_hook_ctx, 0, 5);
    multi_hook_manager_put(inet_getname_v4_p);

    hook_ctx_unregister_func(inet_getname_v6_hook_ctx, 0, 5);
    multi_hook_manager_put(inet_getname_v6_p);
}

static void toa_hook_exit(void)
{
    toa_hook_exit_with_multi_hook();
}


#else


static int toa_hook_func(unsigned long target, unsigned long new, unsigned long* prev_p)
{
    unsigned long prev;
    pte_t* pte_p;
    int level;
    struct page* page;
    void* start = NULL;
    unsigned long* target1 = NULL;


    pte_p = lookup_address(target, &level);
    if  (!pte_p)
        return 0;

    if  (level == PG_LEVEL_4K)
    {   pr_debug("%s: PG_LEVEL_4K\n", __func__);
        page = pte_page(*pte_p);
    }
    else if  (level == PG_LEVEL_2M)
    {
        pr_debug("%s: PG_LEVEL_2M\n", __func__);
        page = pmd_page(*((pmd_t *)pte_p));
        page += pte_index(target);
    }
    else 
    {   pr_debug("%s: pte_p: %d\n", __func__, level);
        return 0;
    }
        
    start = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    if  (!start)
        return -EPERM;
    
    target1 = (unsigned long*)((unsigned long)start | ((unsigned long)target & (PAGE_SIZE - 1)));

    prev = xchg(target1, new);

    if  (prev_p) *prev_p = prev;


    vunmap(start);

    return 0;
}

static int toa_hook_init_native(void)
{
    pr_debug("%s: tcp_v4_syn_rcv_sock_toa: %lx\n", __func__, (unsigned long)tcp_v4_syn_recv_sock_toa);
    pr_debug("%s: tcp_v4_syn_rcv_sock_prev: %lx\n", __func__, *(unsigned long*)syn_recv_sock_v4_p);
    toa_hook_func(syn_recv_sock_v4_p, (unsigned long)tcp_v4_syn_recv_sock_toa, 
            (unsigned long*)&tcp_v4_syn_recv_sock_prev);
    pr_debug("%s: tcp_v4_syn_recv_sock_now: %lx\n", __func__, *(volatile unsigned long*)syn_recv_sock_v4_p);
    pr_debug("%s: tcp_v4_syn_recv_sock_ret: %lx\n", __func__, (unsigned long)tcp_v4_syn_recv_sock_prev);

    pr_debug("%s: tcp_v6_syn_rcv_sock_toa: %lx\n", __func__, (unsigned long)tcp_v6_syn_recv_sock_toa);
    pr_debug("%s: tcp_v6_syn_rcv_sock_prev: %lx\n", __func__, *(unsigned long*)syn_recv_sock_v6_p);
    toa_hook_func(syn_recv_sock_v6_p, (unsigned long)tcp_v6_syn_recv_sock_toa, 
            (unsigned long*)&tcp_v6_syn_recv_sock_prev);
    pr_debug("%s: tcp_v6_syn_recv_sock_now: %lx\n", __func__, *(volatile unsigned long*)syn_recv_sock_v6_p);
    pr_debug("%s: tcp_v6_syn_recv_sock_ret: %lx\n", __func__, (unsigned long)tcp_v6_syn_recv_sock_prev);
    

    toa_hook_func(inet_getname_v4_p, (unsigned long)inet_getname_toa, 
            (unsigned long*)&inet_getname_prev);

    toa_hook_func(inet_getname_v6_p, (unsigned long)inet6_getname_toa, 
            (unsigned long*)&inet6_getname_prev);

    return 0;
}

static int toa_hook_init(void)
{
    if  (toa_hook_init_addr() < 0)
        return -1;

    if  (toa_hook_init_native() < 0)
        return -1;

    return 0;
}

static void toa_hook_exit_native(void)
{
    toa_hook_func(syn_recv_sock_v4_p, (unsigned long)tcp_v4_syn_recv_sock_prev, NULL);

    toa_hook_func(syn_recv_sock_v6_p, (unsigned long)tcp_v6_syn_recv_sock_prev, NULL);

    toa_hook_func(inet_getname_v4_p, (unsigned long)inet_getname_prev, NULL);

    toa_hook_func(inet_getname_v6_p, (unsigned long)inet6_getname_prev, NULL);
}

static void toa_hook_exit(void)
{
    toa_hook_exit_native();
}

#endif



// toa_init --------------------------------------------------------------------------------------------------

static int __init toa_init(void)
{
    pr_info("toa_init begin, version %s\n", toa_version);
    if  (v6_to_v4_prefix_str == NULL) v6_to_v4_prefix_str = v6_to_v4_prefix_str_default;
    
    if  (in6_pton(v6_to_v4_prefix_str, -1, v6_to_v4_prefix_addr, '\0', NULL) <= 0)
    {   pr_warn("bad v6_to_v4_prefix_str %s\n", v6_to_v4_prefix_str);
        goto addr_err;
    }
        
    pr_info("toa init with toa_map_table_bits = %d, vip_enable = %d, v6_to_v4_enable = %d, v6_to_v4_prefix_addr = %pI6\n", 
            toa_map_table_bits, vip_enable, v6_to_v4_enable, v6_to_v4_prefix_addr);
    

    sk_data_ready_addr = kallsyms_lookup_name("sock_def_readable");
    pr_info("%s: CPU[%u]: sk_data_ready_addr = kallsyms_lookup_name(sock_def_readable) = %lx\n",
            __func__, smp_processor_id(), sk_data_ready_addr);
    if  (sk_data_ready_addr == 0)
    {   pr_warn("%s: cannnot find sock_def_readable.\n", __func__);
        goto addr_err;
    }
    
    if  (toa_stats_init() != 0)
    {   pr_warn("toa_stats_init error\n");
        goto stats_err;
    }
        
    if  (toa_map_init() != 0)
    {   pr_warn("toa_map_init error\n");
        goto map_err;
    }
        
    if  (toa_hook_init() != 0)
    {   pr_warn("toa_hook_init error\n");
        goto hook_err;
    }

    pr_info("toa_init end, inserted\n");
    return 0;

hook_err:
    toa_map_exit();
map_err:
    toa_stats_exit();
stats_err:
addr_err:
    pr_warn("toa_init end , failed\n");
    return -1;
}

static void __exit toa_exit(void)
{
    pr_info("toa_exit begin, version %s\n", toa_version);

    toa_hook_exit();
    // the hooked function should protected by rcu, 
    // as in production environment we do not enable preemption, 
    // the rcu_read_lock and rcu_assign_pointere is not necessary, which should also be given attention.
    synchronize_rcu();

    toa_map_exit();
    // to compact with toa-mptcp
    synchronize_rcu();

    vfree(toa_map_table);


    toa_stats_exit();

    pr_info("toa_exit end, rmeoved\n");
    pr_debug("---------------------------------------------\n");
}


module_init(toa_init);
module_exit(toa_exit);
MODULE_LICENSE("GPL");
