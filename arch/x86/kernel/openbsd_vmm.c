// SPDX-License-Identifier: GPL-2.0-only
/*
 * Some code from kvm.c, kvmclock.c. See their copyright notices as well.
 */

/*
 * OpenBSD VMM detection code.
 *
 * Copyright (C) 2020
 * Author: Dave Voutila <voutilad@gmail.com>
 */

#include <linux/clocksource.h>
#include <linux/kvm_para.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/nmi.h>
#include <linux/mm.h>
#include <linux/set_memory.h>
#include <asm/pvclock.h>
#include <asm/msr.h>
#include <asm/hypervisor.h>
#include <asm/x86_init.h>
#include <asm/reboot.h>

#if IS_ENABLED(CONFIG_OPENBSD_VMM_GUEST)

static int vmmclock __initdata = 1;
static int vmmclock_vsyscall __initdata = 1;
static int msr_vmm_system_time __ro_after_init = MSR_KVM_SYSTEM_TIME;
static int msr_vmm_wall_clock __ro_after_init = MSR_KVM_WALL_CLOCK;
static u64 vmm_sched_clock_offset __ro_after_init;

// for pvclock stuff
static u8 valid_flags __read_mostly = 0;

void vmm_pvclock_set_flags(u8 flags)
{
	valid_flags = flags;
}

static atomic64_t last_value = ATOMIC64_INIT(0);

static int __init parse_no_vmmclock(char *arg)
{
	vmmclock = 0;
	return 0;
}
early_param("no-vmmclock", parse_no_vmmclock);

/////////////// kvmclock.c

/* Aligned to page sizes to match whats mapped via vsyscalls to userspace */
#define HV_CLOCK_SIZE	(sizeof(struct pvclock_vsyscall_time_info) * NR_CPUS)
#define HVC_BOOT_ARRAY_SIZE \
	(PAGE_SIZE / sizeof(struct pvclock_vsyscall_time_info))

static struct pvclock_vsyscall_time_info
			hv_clock_boot[HVC_BOOT_ARRAY_SIZE] __bss_decrypted __aligned(PAGE_SIZE);
static struct pvclock_wall_clock wall_clock __bss_decrypted;
static DEFINE_PER_CPU(struct pvclock_vsyscall_time_info *, hv_clock_per_cpu);
static struct pvclock_vsyscall_time_info *hvclock_mem;
// static struct pvclock_vsyscall_time_info *hvclock_mem;

static inline struct pvclock_vcpu_time_info *this_cpu_pvti(void)
{
	return &this_cpu_read(hv_clock_per_cpu)->pvti;
}

static inline struct pvclock_vsyscall_time_info *this_cpu_hvclock(void)
{
	return this_cpu_read(hv_clock_per_cpu);
}
/////////////////////////////////////////////////////////


/////// pvclock.c overrides

u64 vmm_pvclock_clocksource_read(struct pvclock_vcpu_time_info *src)
{
	unsigned version;
	u64 last;
	u8 flags;

	int shift;
	u64 tsc_timestamp, system_time, delta, ctr;
	u32 mul_frac;

	do {
		version = pvclock_read_begin(src);
		flags = src->flags;
		system_time = src->system_time;
		tsc_timestamp = src->tsc_timestamp;
		mul_frac = src->tsc_to_system_mul;
		shift = src->tsc_shift;
	} while (pvclock_read_retry(src, version));

	// via OpenBSD's pvclock.c
	delta = rdtsc() - tsc_timestamp;
	if (shift < 0)
		delta >>= -shift;
	else
		delta <<= shift;
	ctr = ((delta * mul_frac) >> 32) + system_time;

	if ((valid_flags & PVCLOCK_TSC_STABLE_BIT) &&
		(flags & PVCLOCK_TSC_STABLE_BIT))
		return ctr;

	last = atomic64_read(&last_value);
	do {
		if (ctr < last)
			return last;
		last = atomic64_cmpxchg(&last_value, last, ctr);
	} while (unlikely(last != ctr));

	return ctr;
}

void vmm_pvclock_read_wallclock(struct pvclock_wall_clock *wall_clock,
			    struct pvclock_vcpu_time_info *vcpu_time,
			    struct timespec64 *ts)
{
	u32 version;
	u64 delta;
	struct timespec64 now;

	/* get wallclock at system boot */
	do {
		version = wall_clock->version;
		rmb();		/* fetch version before time */
		/*
		 * Note: wall_clock->sec is a u32 value, so it can
		 * only store dates between 1970 and 2106. To allow
		 * times beyond that, we need to create a new hypercall
		 * interface with an extended pvclock_wall_clock structure
		 * like ARM has.
		 */
		now.tv_sec  = wall_clock->sec;
		now.tv_nsec = wall_clock->nsec;
		rmb();		/* fetch time before checking version */
	} while ((wall_clock->version & 1) || (version != wall_clock->version));

	delta = vmm_pvclock_clocksource_read(vcpu_time);	/* time since system boot */
	delta += now.tv_sec * NSEC_PER_SEC + now.tv_nsec;

	now.tv_nsec = do_div(delta, NSEC_PER_SEC);
	now.tv_sec = delta;

	set_normalized_timespec64(ts, now.tv_sec, now.tv_nsec);
}

//////////////////////////////

/*
 * The wallclock is the time of day when we booted. Since then, some time may
 * have elapsed since the hypervisor wrote the data. So we try to account for
 * that with system time
 */
static void vmm_get_wallclock(struct timespec64 *now)
{
	pr_info("[%s]", __func__);
	wrmsrl(msr_vmm_wall_clock, slow_virt_to_phys(&wall_clock));
	preempt_disable();
	vmm_pvclock_read_wallclock(&wall_clock, this_cpu_pvti(), now);
	preempt_enable();
	pr_info("[%s] wallclock: %lld.%ld", __func__, now->tv_sec, now->tv_nsec);
}

static int vmm_set_wallclock(const struct timespec64 *now)
{
	pr_info("[%s] uh oh i shouldn't be called", __func__);
	return -ENODEV;
}

static u64 vmm_clock_read(void)
{
	u64 ret;

	preempt_disable_notrace();
	ret = vmm_pvclock_clocksource_read(this_cpu_pvti());
	preempt_enable_notrace();
	return ret;
}

static u64 vmm_clock_get_cycles(struct clocksource *cs)
{
	return vmm_clock_read();
}

static u64 vmm_sched_clock_read(void)
{
	return vmm_clock_read() - vmm_sched_clock_offset;
}

static inline void vmm_sched_clock_init(bool stable)
{
	pr_info("[%s] stable = %d", __func__, stable);

	if (!stable)
		clear_sched_clock_stable();
	vmm_sched_clock_offset = vmm_clock_read();
	pv_ops.time.sched_clock = vmm_sched_clock_read;

	pr_info("vmm-clock: using sched offset of %llu cycles",
		vmm_sched_clock_offset);

	BUILD_BUG_ON(sizeof(vmm_sched_clock_offset) >
		sizeof(((struct pvclock_vcpu_time_info *)NULL)->system_time));
}

static unsigned long vmm_get_tsc_khz(void)
{
	setup_force_cpu_cap(X86_FEATURE_TSC_KNOWN_FREQ);
	return pvclock_tsc_khz(this_cpu_pvti());
}

//
static void __init vmm_get_preset_lpj(void)
{
	unsigned long khz;
	u64 lpj;

	khz = vmm_get_tsc_khz();

	lpj = ((u64)khz * 1000);
	do_div(lpj, HZ);
	preset_lpj = lpj;
}

////////////////////////////////////////////

struct clocksource vmm_clock = {
	.name	= "vmm-clock",
	.read	= vmm_clock_get_cycles,
	.rating = 1500,
	.mask	= CLOCKSOURCE_MASK(64),
	.flags	= CLOCK_SOURCE_IS_CONTINUOUS,
};
EXPORT_SYMBOL_GPL(vmm_clock);


static void __init vmmclock_init_mem(void)
{
	unsigned long ncpus;
	unsigned int order;
	struct page *p;
	int r;

	if (HVC_BOOT_ARRAY_SIZE >= num_possible_cpus())
		return;

	ncpus = num_possible_cpus() - HVC_BOOT_ARRAY_SIZE;
	order = get_order(ncpus * sizeof(*hvclock_mem));

	p = alloc_pages(GFP_KERNEL, order);
	if (!p) {
		pr_warn("%s: failed to alloc %d pages", __func__, (1U << order));
		return;
	}

	hvclock_mem = page_address(p);

	pr_info("[%s] set hvclock_mem", __func__);

	/*
	 * hvclock is shared between the guest and the hypervisor, must
	 * be mapped decrypted.
	 */
	if (sev_active()) {
		r = set_memory_decrypted((unsigned long) hvclock_mem,
					 1UL << order);
		if (r) {
			__free_pages(p, order);
			hvclock_mem = NULL;
			pr_warn("vmmclock: set_memory_decrypted() failed. Disabling\n");
			return;
		}
	}

	memset(hvclock_mem, 0, PAGE_SIZE << order);
	pr_info("[%s] zeroed and decrypted hvclock_mem", __func__);
}

static int __init vmm_setup_vsyscall_timeinfo(void)
{
	u8 flags;

	if (!per_cpu(hv_clock_per_cpu, 0) || !vmmclock_vsyscall)
		return 0;

	pr_info("[%s] reading flags...", __func__);

	flags = pvclock_read_flags(&hv_clock_boot[0].pvti);
	if (!(flags & PVCLOCK_TSC_STABLE_BIT))
		return 0;

	pr_info("[%s] setting archdata.vclock_mode", __func__);
	vmm_clock.archdata.vclock_mode = VCLOCK_PVCLOCK;

	vmmclock_init_mem();

	return 0;
}
early_initcall(vmm_setup_vsyscall_timeinfo);

//////////////////////////////

static void vmm_register_clock(char *txt)
{
	struct pvclock_vsyscall_time_info *src = this_cpu_hvclock();
	u64 pa;

	if (!src)
		return;

	pa = slow_virt_to_phys(&src->pvti) | 0x01ULL;
	wrmsrl(msr_vmm_system_time, pa);
	pr_info("vmm-clock: cpu %d, msr %llx, %s", smp_processor_id(), pa, txt);
}

static void vmm_save_sched_clock_state(void)
{
}

static void vmm_restore_sched_clock_state(void)
{
	vmm_register_clock("primary cpu clock, resume");
}

static noinline uint32_t __vmm_cpuid_base(void)
{
	if (boot_cpu_data.cpuid_level < 0)
		return 0;

	if (boot_cpu_has(X86_FEATURE_HYPERVISOR))
		return hypervisor_cpuid_base("OpenBSDVMM58", 0);

	return 0;
}

static inline uint32_t vmm_cpuid_base(void)
{
	static int vmm_cpuid_base = -1;

	if (vmm_cpuid_base == -1)
		vmm_cpuid_base = __vmm_cpuid_base();

	return vmm_cpuid_base;
}

static uint32_t __init vmm_detect(void)
{
	return vmm_cpuid_base();
}

bool vmm_para_available(void)
{
	return vmm_cpuid_base() != 0;
}

static void vmm_shutdown(void)
{
	pr_info("[%s] called", __func__);
	native_write_msr(msr_vmm_system_time, 0, 0);
	native_machine_shutdown();
}

/*
 * Copy/pasta from kvmclock.c
 */
void __init vmmclock_init(void)
{
	u8 flags;

	//// MATCHING LOGIC
	if (!vmm_para_available() || !vmmclock) {
		pr_info("[%s] missing condition: !vmm_para_available (%d) OR !vmmclock (%d)...",
		    __func__, !vmm_para_available(), !vmmclock);
		return;
	}

	if (!kvm_para_has_feature(KVM_FEATURE_CLOCKSOURCE2)) {
		pr_info("[%s] could not detect KVM_FEATURE_CLOCKSOURCE2!", __func__);
		return;
	}


	//// ATTACHING LOGIC
	msr_vmm_system_time = MSR_KVM_SYSTEM_TIME_NEW;
	msr_vmm_wall_clock = MSR_KVM_WALL_CLOCK_NEW;

	pr_info("vmm-clock: Using msrs 0x%x and 0x%x",
		msr_vmm_system_time, msr_vmm_wall_clock);

	this_cpu_write(hv_clock_per_cpu, &hv_clock_boot[0]);
	vmm_register_clock("primary cpu clock");
	pvclock_set_pvti_cpu0_va(hv_clock_boot);

	if (kvm_para_has_feature(KVM_FEATURE_CLOCKSOURCE_STABLE_BIT)) {
		pr_info("[%s] stable bit detected", __func__);
		vmm_pvclock_set_flags(PVCLOCK_TSC_STABLE_BIT);
	}

	flags = pvclock_read_flags(&hv_clock_boot[0].pvti);
	vmm_sched_clock_init(flags & PVCLOCK_TSC_STABLE_BIT);

	x86_platform.calibrate_tsc = vmm_get_tsc_khz;
	x86_platform.calibrate_cpu = vmm_get_tsc_khz;
	x86_platform.get_wallclock = vmm_get_wallclock;
	x86_platform.set_wallclock = vmm_set_wallclock;

	// set up some fake state handling for clock_state
	x86_platform.save_sched_clock_state = vmm_save_sched_clock_state;
	x86_platform.restore_sched_clock_state = vmm_restore_sched_clock_state;

	machine_ops.shutdown = vmm_shutdown;

	vmm_get_preset_lpj();

	clocksource_register_hz(&vmm_clock, NSEC_PER_SEC);
	pv_info.name = "OpenBSD VMM";
}

static void __init vmm_init_platform(void)
{
	pr_info("[%s] OPENBSD VMM Hypervisor detected", __func__);
	vmmclock_init();
}

static void __init vmm_guest_init(void)
{
	pr_info("[%s] initializing guest", __func__);
	hardlockup_detector_disable();
}

const __initconst struct hypervisor_x86 x86_hyper_openbsd_vmm = {
	.name			= "OpenBSD VMM",
	.detect			= vmm_detect,
	.type			= X86_HYPER_OPENBSD_VMM,
	.init.init_platform	= vmm_init_platform,
	.init.guest_late_init	= vmm_guest_init,
};
#endif
