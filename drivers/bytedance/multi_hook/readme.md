
# multi_hook 用户手册

## 背景
    在内核中存在一些函数指针可以被用户替换， 但当多个用户同时替换一个函数指针时， 就会发生冲突， 因此需要一种机制来使得多个用户可以同时hook同一个函数指针。

## 用法

```
index: 0, user_ref_cnt: 1, user_func: ffffffff81ce03c8, hook_func: ffffffffc04276b0, desc: tcp_v4_syn_recv_sock 
    prev func 4, func_addr: ffffffffc0370040, enable_post: 0, 
    prev func 6, func_addr: ffffffff81613c70, enable_post: 0, originral func 
    post func 0, func_addr: ffffffffc03700a0, enable_post: 1 
```

    对于一个函数指针， multi_hook提供了若干个prev槽位和若干个post槽位。每个槽位包含一个用户提供的函数指针以及一个是否允许后续函数执行的标志。
    对于一个hook过的函数指针， multi_hook会首先按序遍历prev数组， 顺序执行， 当遇到不允许后续函数执行的标志时， 则直接跳出循环。然后遍历post数组， 顺序执行， 当遇到不允许后续函数执行的标志时， 也直接跳出循环。
    最后一个prev函数的返回值会作为最终的返回值传给post函数进行使用。
    通常最后一个prev函数会被设置成原始函数， 以作为守门员。 当用户需要完整替换掉原始函数时， 只需将enable_post设置为0， 则不会执行到原始函数。当用户只是需要在原始函数之前执行某个功能， 而不影响原始函数的执行时， 应当在prev数组中占据一个槽位， 并将enable_post设置为1。
    

## 示例

下面给出一个实际使用的示例
```
unsigned long syn_recv_sock_v4_func_p;
struct hook_ctx_t *syn_recv_sock_v4_hook_ctx;


struct sock *(*tcp_v4_syn_recv_sock_original_func)(const struct sock *sk,
        struct sk_buff *skb, struct request_sock *req, struct dst_entry *dst, 
        struct request_sock *req_unhash, bool *own_req);

struct sock *tcp_v4_syn_recv_sock_hook_func(const struct sock *sk,
        struct sk_buff *skb, struct request_sock *req, struct dst_entry *dst, 
        struct request_sock *req_unhash, bool *own_req)
{
    pr_debug("tcp_v4_syn_recv_sock_hook_func\n");

    // return tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);
    return tcp_v4_syn_recv_sock_original_func(sk, skb, req, dst, req_unhash, own_req);
}

void tcp_v4_syn_recv_sock_hook_post_func(struct hook_pt_regs *ctx)
{
    pr_debug("tcp_v4_syn_recv_sock_hook_post_func: ret: %lx\n",
            ctx->ret);
}

int syn_recv_sock_test_init(void)
{
    struct inet_connection_sock_af_ops *ipv4_specific_p;
    ipv4_specific_p = (struct inet_connection_sock_af_ops *)
            kallsyms_lookup_name("ipv4_specific");
    if (!ipv4_specific_p) {
        pr_debug("ipv4_specific not found\n");
        return -1;
    }
    syn_recv_sock_v4_func_p = (unsigned long)&ipv4_specific_p->syn_recv_sock;
    pr_debug("func_addr: %lx\n", syn_recv_sock_v4_func_p);

    syn_recv_sock_v4_hook_ctx = multi_hook_manager_get(
            syn_recv_sock_v4_func_p, "tcp_v4_syn_recv_sock");
    if (!syn_recv_sock_v4_hook_ctx)
        return -1;

    if  (hook_ctx_get_original_func(syn_recv_sock_v4_hook_ctx, 
            (unsigned long*)&tcp_v4_syn_recv_sock_original_func) < 0)
        return -1;

    if  (hook_ctx_register_func(syn_recv_sock_v4_hook_ctx, HOOK_CTX_FUNC_PREV_TYPE, 4,
            (unsigned long)tcp_v4_syn_recv_sock_hook_func, 0) < 0)
        return -1;

    if  (hook_ctx_register_func(syn_recv_sock_v4_hook_ctx, HOOK_CTX_FUNC_POST_TYPE, 0,
            (unsigned long)tcp_v4_syn_recv_sock_hook_post_func, HOOK_ENABLE_POST_RUN) < 0)
        return -1;;

    return 0;
}

int syn_recv_sock_test_exit(void)
{
    hook_ctx_unregister_func(syn_recv_sock_v4_hook_ctx, HOOK_CTX_FUNC_PREV_TYPE, 4);
    hook_ctx_unregister_func(syn_recv_sock_v4_hook_ctx, HOOK_CTX_FUNC_POST_TYPE, 0);

    multi_hook_manager_put(syn_recv_sock_v4_func_p);

    return 0;
}
```

### 函数原型

```
struct hook_ctx_t *multi_hook_manager_get(unsigned long addr, const char *desc);

int multi_hook_manager_put(unsigned long addr);

int hook_ctx_get_original_func(struct hook_ctx_t *hook_ctx, unsigned long *func_addr);

int hook_ctx_register_func(struct hook_ctx_t *hook_ctx, enum hook_ctx_func_type type, int index, unsigned long func_addr, unsigned flag);

int hook_ctx_unregister_func(struct hook_ctx_t *hook_ctx, enum hook_ctx_func_type type, int index);
```


    对于一个需要hook的函数指针， 用户首先需要使用multi_hook_manager_get(函数指针地址， description）拿到一个hook_ctx。
    然后使用hook_ctx_register_func去插入具体hook的函数。其中type 为 HOOK_CTX_FUNC_PREV_TYPE 或 HOOK_CTX_FUNC_POST_TYPE。index是在prev或post数组中的序号， 需要共同使用这个hook点的用户线下协商分配。func_addr是插入的函数指针。flag当允许后继函数执行时为HOOK_ENABLE_POST_RUN， 否则为0。
    当用户退出时需要首先使用hook_ctx_unregister_func卸载自己的hook， 然后使用multi_hook_manager_put释放hook_ctx。
    一个需要注意的点是用户需要保证在hook_ctx_register_func和hook_ctx_unregister_func之间的周期内插入的函数一定是可用的， 即如果插入的函数是一个模块函数， 用户需要在这个周期外面进行module_get和module_put。


## 监控

```
root@n016-118-056:/proc/multi_hook_manager# cat stats 
multi_hook_manager, version: 1.0.1 
index: 0, user_ref_cnt: 1, user_func: ffffffff81ce03c8, hook_func: ffffffffc04276b0, desc: tcp_v4_syn_recv_sock 
    prev func 4, func_addr: ffffffffc0370040, enable_post: 0, 
    prev func 6, func_addr: ffffffff81613c70, enable_post: 0, originral func 
    post func 0, func_addr: ffffffffc03700a0, enable_post: 1 
 
index: 1, user_ref_cnt: 0, user_func: 0, hook_func: ffffffffc0427850, desc: 
 
index: 2, user_ref_cnt: 0, user_func: 0, hook_func: ffffffffc04279f0, desc: 
 
index: 3, user_ref_cnt: 0, user_func: 0, hook_func: ffffffffc0427b90, desc: 
```

    multi_hook插入之后会产生一个文件 /proc/multi_hook_manager/stats， 可以用来监控模块的状态。
    multi_hook会预分配一些可以使用的hook点，然后展示每个点的状态。
    index是hook点的序号， user_ref_cnt是使用这个hook点的用户个数， 即multi_hook_manager_get - multi_hook_manager_put， user_func是hook的函数指针的地址， hook_func是预分配的hook函数的地址， desc是用户填入的描述， 多个用户都可以调multi_hook_manager_get填入描述， 但只有第一个使用这个hook点的描述会被保留。
    index下面是prev数组和post数组的状态， func_addr是用户插入的函数地址， 通常prev数组的最后一个函数是原始函数。
    图中所展示的函数的实际执行顺序是： 首先执行prev_func 4, 然后执行post_func 0。
