// SPDX-License-Identifier: GPL-2.0-only
/*
 * OpenBSD VMM detection code.
 *
 * Copyright (C) 2020
 * Author: Dave Voutila <voutilad@gmail.com>
 */

#include <linux/types.h>
#include <linux/printk.h>
#include <asm/hypervisor.h>

#if IS_ENABLED(CONFIG_OPENBSD_VMM_GUEST)

static uint32_t __init vmm_detect(void)
{
	return hypervisor_cpuid_base("OpenBSDVMM58", 0);
}

static void __init vmm_init_platform(void)
{
	// todo
	pr_info("[%s] XXX OPENBSD VMM detected?", __func__);
	kvmclock_init();
}

static void __init vmm_guest_init(void)
{
	pr_info("[%s] initializing guest", __func__);
}

const __initconst struct hypervisor_x86 x86_hyper_openbsd_vmm = {
	.name			= "OpenBSD VMM",
	.detect			= vmm_detect,
	.type			= X86_HYPER_OPENBSD_VMM,
	.init.guest_late_init	= vmm_guest_init,
	.init.init_platform	= vmm_init_platform,
};
#endif
