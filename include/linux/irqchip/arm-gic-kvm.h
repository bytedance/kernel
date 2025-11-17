/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Author: Xu Zhao <zhaoxu.35@bytedance.com>
 */
#ifndef __LINUX_IRQCHIP_ARM_GIC_V4_ITS_H
#define __LINUX_IRQCHIP_ARM_GIC_V4_ITS_H

#define is_v4(its)		(!!((its)->typer & GITS_TYPER_VLPIS))
#define is_v4_1(its)		(!!((its)->typer & GITS_TYPER_VMAPP))

#define gic_data_rdist()		(raw_cpu_ptr(gic_rdists->rdist))
#define gic_data_rdist_cpu(cpu)		(per_cpu_ptr(gic_rdists->rdist, cpu))
#define gic_data_rdist_rd_base()	(gic_data_rdist()->rd_base)
#define gic_data_rdist_vlpi_base()	(gic_data_rdist_rd_base() + SZ_128K)

#define LPI_PROP_DEFAULT_PRIO	GICD_INT_DEF_PRI

#define ITS_FLAGS_CMDQ_NEEDS_FLUSHING		(1ULL << 0)
#define ITS_FLAGS_WORKAROUND_CAVIUM_22375	(1ULL << 1)
#define ITS_FLAGS_WORKAROUND_CAVIUM_23144	(1ULL << 2)
#define ITS_FLAGS_FORCE_NON_SHAREABLE		(1ULL << 3)
#define ITS_FLAGS_WORKAROUND_HISILICON_162100801	(1ULL << 4)
#define ITS_FLAGS_WORKAROUND_HISILICON_162100803	(1ULL << 5)

#ifdef CONFIG_VIRT_VTIMER_IRQ_BYPASS
/* Fetch it from gtdt->virtual_timer_interrupt. */
#define is_vtimer_irq(irq)	((irq) == 27)
#endif

/*
 * Collection structure - just an ID, and a redistributor address to
 * ping. We use one per CPU as a bag of interrupts assigned to this
 * CPU.
 */
struct its_collection {
	u64			target_address;
	u16			col_id;
};

/*
 * The ITS_BASER structure - contains memory information, cached
 * value of BASER register configuration and ITS page size.
 */
struct its_baser {
	void		*base;
	u64		val;
	u32		order;
	u32		psz;
};

struct event_lpi_map {
	unsigned long		*lpi_map;
	u16			*col_map;
	irq_hw_number_t		lpi_base;
	int			nr_lpis;
	raw_spinlock_t		vlpi_lock;
	struct its_vm		*vm;
	struct its_vlpi_map	*vlpi_maps;
	int			nr_vlpis;
};

/*
 * The ITS view of a device - belongs to an ITS, owns an interrupt
 * translation table, and a list of interrupts.  If it some of its
 * LPIs are injected into a guest (GICv4), the event_map.vm field
 * indicates which one.
 */
struct its_device {
	struct list_head	entry;
	struct its_node		*its;
	struct event_lpi_map	event_map;
	void			*itt;
	u32			nr_ites;
	u32			device_id;
	bool			shared;

#ifdef CONFIG_VIRT_PLAT_DEV
	/* For virtual devices which needed the devid managed */
	bool			is_vdev;
	struct rsv_devid_pool	*devid_pool;
#endif
};

/*
 * The ITS command block, which is what the ITS actually parses.
 */
struct its_cmd_block {
	union {
		u64	raw_cmd[4];
		__le64	raw_cmd_le[4];
	};
};

/*
 * The ITS structure - contains most of the infrastructure, with the
 * top-level MSI domain, the command queue, the collections, and the
 * list of devices writing to it.
 *
 * dev_alloc_lock has to be taken for device allocations, while the
 * spinlock must be taken to parse data structures such as the device
 * list.
 */
struct its_node {
	raw_spinlock_t		lock;
	struct mutex		dev_alloc_lock;
	struct list_head	entry;
	void __iomem		*base;
	void __iomem		*sgir_base;
	phys_addr_t		phys_base;
	struct its_cmd_block	*cmd_base;
	struct its_cmd_block	*cmd_write;
	struct its_baser	tables[GITS_BASER_NR_REGS];
	struct its_collection	*collections;
	struct fwnode_handle	*fwnode_handle;
	u64			(*get_msi_base)(struct its_device *its_dev);
	u64			typer;
	u64			cbaser_save;
	u32			ctlr_save;
	u32			mpidr;
	struct list_head	its_device_list;
	u64			flags;
	unsigned long		list_nr;
	int			numa_node;
	unsigned int		msi_domain_flags;
	u32			pre_its_base; /* for Socionext Synquacer */
#ifdef CONFIG_VIRT_VTIMER_IRQ_BYPASS
	u32			version;
#endif
	int			vlpi_redist_offset;
};

typedef int (*vcpu_affinity_func_t)(struct irq_data *data, void *vcpu_info);

extern struct list_head its_nodes;
extern unsigned long its_list_map;
extern struct rdists *gic_rdists;
extern struct gic_kvm_info *gic_kvm_info;
extern struct irq_domain *gic_domain;
void its_send_vmovi(struct its_device *dev, u32 id);
void its_map_vm(struct its_node *its, struct its_vm *vm);
void lpi_write_config(struct irq_data *d, u8 clr, u8 set);
void its_send_discard(struct its_device *dev, u32 id);
void its_send_vmapti(struct its_device *dev, u32 id);
void its_send_mapti(struct its_device *dev, u32 irq_id, u32 id);
void lpi_update_config(struct irq_data *d, u8 clr, u8 set);
void its_unmap_vm(struct its_node *its, struct its_vm *vm);
struct its_vlpi_map *get_vlpi_map(struct irq_data *d);
void its_wait_vpt_parse_complete(void);
int its_gic_v4_init(const struct irq_domain_ops *vpe_domain,
		    const struct irq_domain_ops *sgi_domain,
		    vcpu_affinity_func_t affinity_func);
void its_gic_v4_uninit(void);
bool gic_requires_eager_mapping(void);
bool rdists_support_shareable(void);
void its_vpe_send_inv(struct irq_data *d);
u32 its_get_lpi_nr_bits(void);
unsigned long its_get_lpi_pendbase_sz(void);
unsigned long its_get_lpi_propbase_sz(void);
void its_lpi_free(unsigned long *bitmap, u32 base, u32 nr_ids);
unsigned long *its_lpi_alloc(int nr_irqs, u32 *base, int *nr_ids);
void gic_reset_prop_table(void *va);
int its_irq_gic_domain_alloc(struct irq_domain *domain,
			     unsigned int virq,
			     irq_hw_number_t hwirq);
bool its_alloc_vpe_table(u32 vpe_id);
void its_vlpi_set_doorbell(struct irq_data *d, bool enable);
struct its_node *find_4_1_its(void);
void its_send_invdb(struct its_node *its, struct its_vpe *vpe);
void its_configure_sgi(struct irq_data *d, bool clear);
u64 its_clear_vpend_valid(void __iomem *vlpi_base, u64 clr, u64 set);
void its_vpe_db_proxy_unmap(struct its_vpe *vpe);
void its_send_vmovp(struct its_vpe *vpe);
void its_vpe_db_proxy_move(struct its_vpe *vpe, int from, int to);
void its_send_vmapp(struct its_node *its, struct its_vpe *vpe, bool valid);
void its_send_vinvall(struct its_node *its, struct its_vpe *vpe);
void its_send_int(struct its_device *dev, u32 event_id);
void its_send_clear(struct its_device *dev, u32 event_id);
int its_vlpi_get(struct irq_data *d, struct its_cmd_info *info);
void its_vpe_send_cmd(struct its_vpe *vpe,
			     void (*cmd)(struct its_device *, u32));

void its_set_kvm_vcpu_affinity(vcpu_affinity_func_t affinity_func);
int its_set_kvm_v4_domain_ops(const struct irq_domain_ops *vpe_ops,
			  const struct irq_domain_ops *sgi_ops);
#endif /* __LINUX_IRQCHIP_ARM_GIC_V4_ITS_H */
