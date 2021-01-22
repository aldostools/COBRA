//----------------------------------------
//KERNEL PATCH
//----------------------------------------
#define DO_PATCH_KERNEL_PATCH
//----------------------------------------
#ifdef DO_PATCH_KERNEL_PATCH
typedef struct
{
	uint32_t address;
	uint32_t data;
} Patch;

static Patch kernel_patches[] =
{
	{ patch_data1_offset, 0x01000000 },
	{ patch_func8_offset1, LI(R3, 0) }, // force lv2open return 0

	// disable calls in lv2open to lv1_send_event_locally which makes the system crash
	{ patch_func8_offset2, NOP },
	{ patch_func9_offset, NOP }, // 4.30 - watch: additional call after

	// psjailbreak, PL3, etc destroy this function to copy their code there.
	// We don't need that, but let's dummy the function just in case that patch is really necessary
	{ mem_base2, LI(R3, 1) },
	{ mem_base2 + 4, BLR },

	#ifdef DO_PATCH_PS2
	// sys_sm_shutdown, for ps2 let's pass to copy_from_user a fourth parameter
	{ shutdown_patch_offset, MR(R6, R31) },
	{ module_sdk_version_patch_offset, NOP },
	#endif
	// User thread prio hack (needed for netiso)
	{ user_thread_prio_patch, NOP },
	{ user_thread_prio_patch2, NOP },
	// ODE Protection removal (needed for CFW 4.60+)
	#ifdef lic_patch
	{ lic_patch, LI(R3, 1) },
	#endif
	#ifdef ode_patch
	{ ode_patch, LI(R3, 0) },
	{ ode_patch + 4, STD(R3, 0, R9) },
	#endif
};

#define N_KERNEL_PATCHES	(sizeof(kernel_patches) / sizeof(Patch))

static INLINE void apply_kernel_patches(void)
{
	for (int i = 0; i < N_KERNEL_PATCHES; i++)
	{
		uint32_t *addr= (uint32_t *)MKA(kernel_patches[i].address);
		*addr = kernel_patches[i].data;
		clear_icache(addr, 4);
	}
}

#endif

////////////////////////////////////////////////////////////////////////////

void do_patch(uint64_t addr, uint64_t patch)
{
	*(uint64_t *)addr = patch;
	clear_icache((void *)addr, 8);
}

void do_patch32(uint64_t addr, uint32_t patch)
{
	*(uint32_t *)addr = patch;
	clear_icache((void *)addr, 4);
}

