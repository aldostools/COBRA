#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/memory.h>
#include <lv2/patch.h>
#include <lv2/syscall.h>
#include <lv2/usb.h>
#include <lv2/storage.h>
#include <lv2/thread.h>
#include <lv2/synchronization.h>
#include <lv2/modules.h>
#include <lv2/io.h>
#include <lv2/time.h>
#include <lv2/security.h>
#include <lv2/error.h>
#include <lv2/symbols.h>
#include <lv2/syscall.h>
#include <lv1/stor.h>
#include <lv1/patch.h>
#include "common.h"
#include "syscall8.h"
//#include "cobra.h"
#include "modulespatch.h"

#include "mappath.h"
#include "storage_ext.h"
#include "region.h"
#include "permissions.h"
#include "psp.h"
#include "config.h"
#include "drm.h"
#include "sm_ext.h"
#include "laboratory.h"
#include "ps3mapi_core.h"

#include "kernel_payload.h"
#include "lv2_patches.h"
#include "vsh_patches.h"
#include "peek_poke.h"
#include "fan_control.h"
#include "reactPSN.h"
#include "qa_flag.h"

// Format of version:
// byte 0, 7 MS bits -> reserved
// byte 0, 1 LS bit -> 1 = CFW version, 0 = OFW/exploit version
// byte 1 and 2 -> ps3 fw version in BCD e.g 3.55 = 03 55. For legacy reasons, 00 00 means 3.41
// byte 3 is cobra firmware version,
// 1 = version 1.0-1.2,
// 2 = 2.0,
// 3 = 3.0
// 4 = 3.1
// 5 = 3.2
// 6 = 3.3
// 7 = 4.0
// 8 = 4.1
// 9 = 4.2
// A = 4.3
// B = 4.4
// C = 5.0
// D = 5.1
// E = 6.0
// F = 7.0

#define CB_LOCATION 	"/dev_blind/rebug/cobra/stage2.cex"
#define CB_LOCATION_DEX "/dev_blind/rebug/cobra/stage2.dex"

#define COBRA_VERSION		0x0F
#define COBRA_VERSION_BCD	0x0830

#if defined(FIRMWARE_4_84) || defined(FIRMWARE_4_84DEX)
#define FIRMWARE_VERSION	0x0484
#elif defined(FIRMWARE_4_85) || defined(FIRMWARE_4_85DEX)
#define FIRMWARE_VERSION	0x0485
#elif defined(FIRMWARE_4_86) || defined(FIRMWARE_4_86DEX)
#define FIRMWARE_VERSION	0x0486
#endif

#if defined(CFW)
	#define IS_CFW			1
#else
	#define IS_CFW			0
#endif

#define MAKE_VERSION(cobra, fw, type) ((cobra&0xFF) | ((fw&0xffff)<<8) | ((type&0x1)<<24))


int disable_cobra_stage()
{
	cellFsUtilMount_h("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0, 0);
	cellFsRename(CB_LOCATION, CB_LOCATION".bak");
	cellFsRename(CB_LOCATION_DEX, CB_LOCATION_DEX".bak");
	uint64_t size = 0x5343450000000000;
	int dst;
	cellFsOpen("/dev_hdd0/tmp/loadoptical", CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &dst, 0666, NULL, 0);
	cellFsWrite(dst, &size, 4, &size);
	cellFsClose(dst);
	return 0;
}
/*
int disable_cobra_stage()
{
	cellFsUtilMount_h("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0, 0);
	CellFsStat stat, stat_DEX; // For CEX and DEX stages
	cellFsStat(CB_LOCATION, &stat);
	cellFsStat(CB_LOCATION_DEX, &stat_DEX);
	uint64_t len = stat.st_size;
	uint64_t len_DEX = stat_DEX.st_size;
	uint8_t *buf;
	uint64_t size;
	int src, dst;

	page_allocate_auto(NULL, 0x40000, 0x2F, (void **)&buf);

	// CEX
	if (cellFsOpen(CB_LOCATION, CELL_FS_O_RDONLY, &src, 0, NULL, 0) == 0)
	{
		cellFsRead(src, buf, len, &size);
		cellFsClose(src);
	}
	else
	{
		page_free(NULL, buf, 0x2F);
		return -1;
	}

	if (cellFsOpen(CB_LOCATION".bak", CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &dst, 0666, NULL, 0) == 0)
	{
		cellFsWrite(dst, buf, len, &size);
		cellFsClose(dst);
	}
	else
	{
		page_free(NULL, buf, 0x2F);
		return -1;
	}

	//DEX
	if (cellFsOpen(CB_LOCATION_DEX, CELL_FS_O_RDONLY, &src, 0, NULL, 0) == 0)
	{
		cellFsRead(src, buf, len_DEX, &size);
		cellFsClose(src);
	}
	else
	{
		page_free(NULL, buf, 0x2F);
		return -1;
	}

	if (cellFsOpen(CB_LOCATION_DEX".bak", CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &dst, 0666, NULL, 0) == 0)
	{
		cellFsWrite(dst, buf, len_DEX, &size);
		cellFsClose(dst);
	}
	else
	{
		page_free(NULL, buf, 0x2F);
		return -1;
	}

	page_free(NULL, buf, 0x2F);
	cellFsUnlink(CB_LOCATION);
	cellFsUnlink(CB_LOCATION_DEX);
	size = 0x5343450000000000;
	cellFsOpen("/dev_hdd0/tmp/loadoptical", CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &dst, 0666, NULL, 0);
	cellFsWrite(dst, &size, 4, &size);
	cellFsClose(dst);
	return 0;
}
*/
f_desc_t extended_syscall8;

int64_t syscall8(uint64_t function, uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4, uint64_t param5, uint64_t param6, uint64_t param7);

static INLINE int sys_get_version(uint32_t *version)
{
	uint32_t pv = MAKE_VERSION(COBRA_VERSION, FIRMWARE_VERSION, IS_CFW);
	return copy_to_user(&pv, get_secure_user_ptr(version), sizeof(uint32_t));
}

static INLINE int sys_get_version2(uint16_t *version)
{
	uint16_t cb = COBRA_VERSION_BCD;
	return copy_to_user(&cb, get_secure_user_ptr(version), sizeof(uint16_t));
}

/*
LV2_HOOKED_FUNCTION(uint64_t, sys_cfw_storage_send_device_command, (uint32_t device_handle, unsigned int command, void indata, uint64_t inlen, void outdata, uint64_t outlen))
{
 DPRINTF("sys_storage_send_device_command\n");

 sys_storage_send_device_command(device_handle, command, indata, inlen, outdata, outlen);
 int64_t debug_print(const char* buffer, size_t size);
 void debug_print_hex(void *buf, uint64_t size);
 void debug_print_hex_c(void *buf, uint64_t size);

}
*/

extern f_desc_t open_path_callback;

extern uint8_t auto_dev_blind;	// homebrew_blocker.h
extern uint8_t allow_create_sc; // homebrew_blocker.h
extern uint8_t photo_gui;		// mappath.c

static inline void ps3mapi_unhook_all(void)
{
	unhook_all_modules();
	unhook_all_region();
	unhook_all_map_path();
    unhook_all_storage_ext();
	//unhook_all_permissions();
}

static uint64_t ps3mapi_key = 0;
static uint8_t ps3mapi_access_tries = 0;
static uint8_t ps3mapi_access_granted = 1;

static int ps3mapi_partial_disable_syscall8 = 0;
static uint8_t disable_cobra = 0;

uint64_t LV2_OFFSET_ON_LV1 = 0; // 0x1000000 on 4.46, 0x8000000 on 4.76
uint64_t lv2_offset = 0;
LV2_SYSCALL2(int64_t, syscall8, (uint64_t function, uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4, uint64_t param5, uint64_t param6, uint64_t param7))
{
	extend_kstack(0);

	//DPRINTF("Syscall 8 -> %lx\n", function);
	if(function>=0x8000000000000000ULL)
		DPRINTF("LV1 peek %lx %llux\n", function, (long long unsigned int)(lv1_peekd(function)));

	// -- AV: temporary disable cobra syscall (allow dumpers peek 0x1000 to 0x9800)
	static uint8_t tmp_lv1peek = 0;

	if(ps3mapi_partial_disable_syscall8 == 0 && extended_syscall8.addr == 0 && ps3mapi_access_granted)
	{
		if((function >= 0x9800) || (function & 3))
			tmp_lv1peek=0; else

		if(function <= 0x1000)
		{
			tmp_lv1peek=1;

			if(function <= SYSCALL8_OPCODE_ENABLE_COBRA)
			{
				if(param1>=SYSCALL8_DISABLE_COBRA_CAPABILITY)
					return (param1==SYSCALL8_DISABLE_COBRA_CAPABILITY) ? SYSCALL8_DISABLE_COBRA_OK : disable_cobra;
				else
					disable_cobra = (function==SYSCALL8_OPCODE_DISABLE_COBRA && param1==1);
			}
		}

		if(tmp_lv1peek)
			return lv1_peekd(function);
	}
	else
		tmp_lv1peek=0;
	// --

/*
	static uint32_t pid_blocked = 0;
	uint32_t pid;

	// Some processsing to avoid crashes with lv1 dumpers
	pid = get_current_process_critical()->pid;

	if (pid == pid_blocked)
	{
		if (function <= 0x1000 || function >= 0x9800 || (function & 3)) // * Keep all cobra opcodes below 0x9800 * /
		{
			DPRINTF("App was unblocked from using syscall8\n");
			pid_blocked = 0;
		}
		else
		{
			DPRINTF("App was blocked from using syscall8\n");
			return ENOSYS;
		}
	}

	if (function == (SYSCALL8_OPCODE_GET_VERSION-8))
	{
		// 0x6FF8. On 0x7000 it *could* crash
		pid_blocked = pid;
		return ENOSYS;
	}
	else if (function == (SYSCALL8_OPCODE_PSP_POST_SAVEDATA_INITSTART-8))
	{
		// 0x3000, On 0x3008 it *could* crash
		pid_blocked = pid;
		return ENOSYS;
	}
*/

	if ((function == SYSCALL8_OPCODE_PS3MAPI) && ((int)param1 == PS3MAPI_OPCODE_REQUEST_ACCESS) && (param2 == ps3mapi_key) && (ps3mapi_access_tries < 3))
	{
		ps3mapi_access_tries = 0;
		ps3mapi_access_granted = 1;
	}

	if((!ps3mapi_access_granted) && (ps3mapi_key != 0))
	{
		ps3mapi_access_tries += 1;

		if(ps3mapi_access_tries > 3)
			ps3mapi_access_tries = 99;

		return ENOSYS;
	}

	if (3 <= ps3mapi_partial_disable_syscall8)
	{
		if (function == SYSCALL8_OPCODE_PS3MAPI && ps3mapi_access_granted)
		{
			if ((int)param1 == PS3MAPI_OPCODE_PDISABLE_SYSCALL8)
			{
				ps3mapi_partial_disable_syscall8 = (int)param2;
				return SUCCEEDED;
			}
			else if ((int)param1 == PS3MAPI_OPCODE_PCHECK_SYSCALL8)
				return ps3mapi_partial_disable_syscall8;
			else return ENOSYS;
		}
		else
			return ENOSYS;
	}

	if ((function != SYSCALL8_OPCODE_PS3MAPI) && (2 <= ps3mapi_partial_disable_syscall8))
		return ENOSYS;

	// -- AV: disable cobra without reboot (use lv1 peek)
	if(disable_cobra)
		return lv1_peekd(function);

	switch (function)
	{
		case SYSCALL8_OPCODE_PS3MAPI:
			switch ((int)param1)
			{
				//DPRINTF("syscall8: PS3M_API function 0x%x\n", (int)param1);

				//----------
				//CORE
				//----------
				case PS3MAPI_OPCODE_GET_CORE_VERSION:
					return PS3MAPI_CORE_VERSION;
				break;
				case PS3MAPI_OPCODE_GET_CORE_MINVERSION:
					return PS3MAPI_CORE_MINVERSION;
				break;
				case PS3MAPI_OPCODE_GET_FW_VERSION:
					return PS3MAPI_FW_VERSION;
				break;
				case PS3MAPI_OPCODE_GET_FW_TYPE:
					return ps3mapi_get_fw_type((char *)param2);
				break;

				//----------------
				//PEEK & POKE (av)
				//----------------
				case PS3MAPI_OPCODE_SUPPORT_SC8_PEEK_POKE:
					return PS3MAPI_OPCODE_SUPPORT_SC8_PEEK_POKE_OK;
				break;
				case PS3MAPI_OPCODE_LV1_PEEK:
					return lv1_peekd(param2);
				break;
				case PS3MAPI_OPCODE_LV1_POKE:
					lv1_poked(param2, param3);
					return SUCCEEDED;
				break;
				case PS3MAPI_OPCODE_LV2_PEEK:
					return lv1_peekd(param2+LV2_OFFSET_ON_LV1);
				break;
				case PS3MAPI_OPCODE_LV2_POKE:
					lv1_poked(param2+LV2_OFFSET_ON_LV1, param3);
					return SUCCEEDED;
				break;

				//----------
				//SECURITY
				//----------
				case PS3MAPI_OPCODE_SET_ACCESS_KEY:
					ps3mapi_key = param2;
					ps3mapi_access_granted = 0;
					ps3mapi_access_tries = 0;
					return SUCCEEDED;

				//----------
				//PROCESS
				//----------
				case PS3MAPI_OPCODE_GET_ALL_PROC_PID:
					return ps3mapi_get_all_processes_pid((process_id_t *)param2);
				break;
				case PS3MAPI_OPCODE_GET_PROC_NAME_BY_PID:
					return ps3mapi_get_process_name_by_pid((process_id_t)param2, (char *)param3);
				break;
				case PS3MAPI_OPCODE_GET_PROC_BY_PID:
					return ps3mapi_get_process_by_pid((process_id_t)param2, (process_t)param3);
				break;
				case PS3MAPI_OPCODE_GET_CURRENT_PROC:
					return ps3mapi_get_current_process((process_t)param2);
				break;
				case PS3MAPI_OPCODE_GET_CURRENT_PROC_CRIT:
					return ps3mapi_get_current_process_critical((process_t)param2);
				break;

				//----------
				//MEMORY
				//----------
				case PS3MAPI_OPCODE_GET_PROC_MEM:
					return ps3mapi_get_process_mem((process_id_t)param2, param3, (char *)param4, (int)param5);
				break;
				case PS3MAPI_OPCODE_SET_PROC_MEM:
					return ps3mapi_set_process_mem((process_id_t)param2, param3, (char *)param4, (int)param5);
				break;
				case PS3MAPI_OPCODE_PROC_PAGE_ALLOCATE:
					return ps3mapi_process_page_allocate((process_id_t)param2, param3, param4, param5, param6, (uint64_t *)param7); // TheRouletteBoi
				break;

				//----------
				//MODULE
				//----------
				case PS3MAPI_OPCODE_GET_ALL_PROC_MODULE_PID:
					return ps3mapi_get_all_process_modules_prx_id((process_id_t)param2, (sys_prx_id_t *)param3);
				break;
				case PS3MAPI_OPCODE_GET_PROC_MODULE_NAME:
					return ps3mapi_get_process_module_name_by_prx_id((process_id_t)param2, (sys_prx_id_t)param3, (char *)param4);
				break;
				case PS3MAPI_OPCODE_GET_PROC_MODULE_FILENAME:
					return ps3mapi_get_process_module_filename_by_prx_id((process_id_t)param2, (sys_prx_id_t)param3, (char *)param4);
				break;
				case PS3MAPI_OPCODE_GET_PROC_MODULE_INFO:
					return ps3mapi_get_process_module_info((process_t)param2, (sys_prx_id_t)param3, (char *)param4, (char *)param5);
				break;
				case PS3MAPI_OPCODE_GET_PROC_MODULE_SEGMENTS:
					return ps3mapi_get_process_module_segments((process_id_t)param2, (sys_prx_id_t)param3, (sys_prx_module_info_t *)param4); // TheRouletteBoi
				break;
				case PS3MAPI_OPCODE_LOAD_PROC_MODULE:
					return ps3mapi_load_process_modules((process_id_t)param2, (char *)param3, (void *)param4, (uint32_t)param5);
				break;
				case PS3MAPI_OPCODE_UNLOAD_PROC_MODULE:
					return ps3mapi_unload_process_modules((process_id_t)param2, (sys_prx_id_t)param3);
				break;

				//----------
				//VSH PLUGINS
				//----------
				case PS3MAPI_OPCODE_UNLOAD_VSH_PLUGIN:
					return ps3mapi_unload_vsh_plugin((char *)param2);
				break;
				case PS3MAPI_OPCODE_GET_VSH_PLUGIN_INFO:
					return ps3mapi_get_vsh_plugin_info((unsigned int)param2, (char *)param3, (char *)param4);
				break;
				case PS3MAPI_OPCODE_GET_VSH_PLUGIN_BY_NAME:
					return ps3mapi_get_vsh_plugin_slot_by_name((char *)param2, (uint8_t)param3);
				break;
				//----------
				//SYSCALL
				//----------
				case PS3MAPI_OPCODE_DISABLE_SYSCALL:
					return ps3mapi_disable_syscall((int)param2);
				break;
				case PS3MAPI_OPCODE_CHECK_SYSCALL:
					return ps3mapi_check_syscall((int)param2);
				break;
				case PS3MAPI_OPCODE_PDISABLE_SYSCALL8:
					ps3mapi_partial_disable_syscall8 = (int)param2;
					return SUCCEEDED;
				break;
				case PS3MAPI_OPCODE_PCHECK_SYSCALL8:
					return ps3mapi_partial_disable_syscall8;
				break;
// 8.2
				case PS3MAPI_OPCODE_CREATE_CFW_SYSCALLS:
					create_syscalls();
					return SUCCEEDED;
				break;
				case PS3MAPI_OPCODE_ALLOW_CREATE_SYSCALLS:
					allow_create_sc = (uint8_t)param2; // 1 = allow, 0 = do not allow
					return SUCCEEDED;
				break;
				//----------
				//REMOVE HOOK
				//----------
				case PS3MAPI_OPCODE_REMOVE_HOOK:
					ps3mapi_unhook_all(); //REMOVE ALL "MAMBA/COBRA" HOOK
					return SUCCEEDED;
				break;

				//-----------
				//PSID/IDPS
				//-----------
				case PS3MAPI_OPCODE_GET_IDPS:
					return ps3mapi_get_idps((uint64_t *)param2);
				break;
				case PS3MAPI_OPCODE_SET_IDPS:
					return ps3mapi_set_idps(param2, param3);
				break;
				case PS3MAPI_OPCODE_GET_PSID:
					return ps3mapi_get_psid((uint64_t *)param2);
				break;
				case PS3MAPI_OPCODE_SET_PSID:
					return ps3mapi_set_psid(param2, param3);
				break;
// 8.2
				//----------
				//MISC
				//----------
				case PS3MAPI_OPCODE_AUTO_DEV_BLIND:
					auto_dev_blind = (uint8_t)param2;
					return auto_dev_blind;
				break;

				case PS3MAPI_OPCODE_PHOTO_GUI:
					photo_gui = (uint8_t)param2;
					return photo_gui;
				break;

				#ifdef FAN_CONTROL
				case PS3MAPI_OPCODE_SET_FAN_SPEED:
					if(param2 == 1)
						do_fan_control();
					else
						fan_control_running = 0;

					return sm_set_fan_policy(0, (uint8_t)(param2 >= 0x33 ? 2 : 1), (uint8_t)(param2 >= 0x33 ? param2 : 0));
				break;

				case PS3MAPI_OPCODE_GET_FAN_SPEED:
					return sm_get_fan_speed();
				break;
				#endif
				//----------
				//DEFAULT
				//----------
				default:
					DPRINTF("syscall8: Unsupported PS3M_API opcode: 0x%lx\n", function);
					return ENOSYS;
				break;
			}
		break;

		case SYSCALL8_OPCODE_STEALTH_TEST:  //KW PSNPatch stealth extension compatibility
			return SYSCALL8_STEALTH_OK;
		break;

		case SYSCALL8_OPCODE_STEALTH_ACTIVATE: //KW PSNPatch stealth extension compatibility
		{
				uint64_t syscall_not_impl = *(uint64_t *)MKA(syscall_table_symbol);
				//*(uint64_t *)MKA(syscall_table_symbol+ 8* 8) = syscall_not_impl;
				ps3mapi_partial_disable_syscall8 = 2; //NzV Edit: Keep PS3M_API Features only.
				*(uint64_t *)MKA(syscall_table_symbol + 8 * 9) = syscall_not_impl;
				*(uint64_t *)MKA(syscall_table_symbol + 8 * 10) = syscall_not_impl;
				*(uint64_t *)MKA(syscall_table_symbol + 8 * 11) = syscall_not_impl;
				*(uint64_t *)MKA(syscall_table_symbol + 8 * 15) = syscall_not_impl;
				*(uint64_t *)MKA(syscall_table_symbol + 8 * 35) = syscall_not_impl;
				*(uint64_t *)MKA(syscall_table_symbol + 8 * 36) = syscall_not_impl;
				*(uint64_t *)MKA(syscall_table_symbol + 8 * 38) = syscall_not_impl;
				*(uint64_t *)MKA(syscall_table_symbol + 8 * 6) = syscall_not_impl;
				*(uint64_t *)MKA(syscall_table_symbol + 8 * 7) = syscall_not_impl;
			return SYSCALL8_STEALTH_OK;
		}
		break;

		//--------------------------
		// STORAGE
		//--------------------------
		case SYSCALL8_OPCODE_GET_DISC_TYPE:
			return sys_storage_ext_get_disc_type((unsigned int *)param1, (unsigned int *)param2, (unsigned int *)param3);
		break;

		case SYSCALL8_OPCODE_READ_PS3_DISC:
			return sys_storage_ext_read_ps3_disc((void *)param1, param2, (uint32_t)param3);
		break;

		case SYSCALL8_OPCODE_FAKE_STORAGE_EVENT:
			return sys_storage_ext_fake_storage_event(param1, param2, param3);
		break;

		case SYSCALL8_OPCODE_GET_EMU_STATE:
			return sys_storage_ext_get_emu_state((sys_emu_state_t *)param1);
		break;

		case SYSCALL8_OPCODE_USE_PS2NETEMU:
			return bc_to_net((int)param1);
		break;

		//--------------------------
		// COBRA VERSION
		//--------------------------
		case SYSCALL8_OPCODE_GET_VERSION:
			return sys_get_version((uint32_t *)param1);
		break;

		case SYSCALL8_OPCODE_GET_VERSION2:
			return sys_get_version2((uint16_t *)param1);
		break;

		//--------------------------
		// MOUNT
		//--------------------------
		case SYSCALL8_OPCODE_MOUNT_PS3_DISCFILE:
			return sys_storage_ext_mount_ps3_discfile(param1, (char **)param2);
		break;

		case SYSCALL8_OPCODE_MOUNT_DVD_DISCFILE:
			return sys_storage_ext_mount_dvd_discfile(param1, (char **)param2);
		break;

		case SYSCALL8_OPCODE_MOUNT_BD_DISCFILE:
			return sys_storage_ext_mount_bd_discfile(param1, (char **)param2);
		break;

		case SYSCALL8_OPCODE_MOUNT_PSX_DISCFILE:
			return sys_storage_ext_mount_psx_discfile((char *)param1, param2, (ScsiTrackDescriptor *)param3);
		break;

		case SYSCALL8_OPCODE_MOUNT_PS2_DISCFILE:
			return sys_storage_ext_mount_ps2_discfile(param1, (char **)param2, param3, (ScsiTrackDescriptor *)param4);
		break;

		case SYSCALL8_OPCODE_MOUNT_DISCFILE_PROXY:
			return sys_storage_ext_mount_discfile_proxy(param1, param2, param3, param4, param5, param6, (ScsiTrackDescriptor *)param7);
		break;

		case SYSCALL8_OPCODE_UMOUNT_DISCFILE:
			return sys_storage_ext_umount_discfile();
		break;

		case SYSCALL8_OPCODE_MOUNT_ENCRYPTED_IMAGE:
			return sys_storage_ext_mount_encrypted_image((char *)param1, (char *)param2, (char *)param3, param4);

		//--------------------------
		// KERNEL PAYLOAD
		//--------------------------
		case SYSCALL8_OPCODE_RUN_PAYLOAD:
			return inst_and_run_kernel((uint8_t *)param1, param2);
		break;

		case SYSCALL8_OPCODE_RUN_PAYLOAD_DYNAMIC:
			return inst_and_run_kernel_dynamic((uint8_t *)param1, param2, (uint64_t *)param3);
		break;

		case SYSCALL8_OPCODE_UNLOAD_PAYLOAD_DYNAMIC:
			return unload_plugin_kernel(param1);
		break;

		//--------------------------
		// PERMISSIONS
		//--------------------------
		case SYSCALL8_OPCODE_GET_ACCESS:
			return sys_permissions_get_access();
		break;

		case SYSCALL8_OPCODE_REMOVE_ACCESS:
			return sys_permissions_remove_access();
		break;

		//--------------------------
		// CONFIG
		//--------------------------
		case SYSCALL8_OPCODE_READ_COBRA_CONFIG:
			return sys_read_cobra_config((CobraConfig *)param1);
		break;

		case SYSCALL8_OPCODE_WRITE_COBRA_CONFIG:
			return sys_write_cobra_config((CobraConfig *)param1);
		break;

		//--------------------------
		// PSP
		//--------------------------
		case SYSCALL8_OPCODE_SET_PSP_UMDFILE:
			vsh_process = get_vsh_process(); //NzV
			if(vsh_process) get_vsh_offset();
			return sys_psp_set_umdfile((char *)param1, (char *)param2, param3);
		break;

		case SYSCALL8_OPCODE_SET_PSP_DECRYPT_OPTIONS:
			return sys_psp_set_decrypt_options(param1, param2, (uint8_t *)param3, param4, param5, (uint8_t *)param6, param7);
		break;

		case SYSCALL8_OPCODE_READ_PSP_HEADER:
			return sys_psp_read_header(param1, (char *)param2, param3, (uint64_t *)param4);
		break;

		case SYSCALL8_OPCODE_READ_PSP_UMD:
			return sys_psp_read_umd(param1, (void *)param2, param3, param4, param5);
		break;

		case SYSCALL8_OPCODE_PSP_PRX_PATCH:
			return sys_psp_prx_patch((uint32_t *)param1, (uint8_t *)param2, (void *)param3);
		break;

		case SYSCALL8_OPCODE_PSP_CHANGE_EMU:
			return sys_psp_set_emu_path((char *)param1);
		break;

		case SYSCALL8_OPCODE_PSP_POST_SAVEDATA_INITSTART:
			return sys_psp_post_savedata_initstart(param1, (void *)param2);
		break;

		case SYSCALL8_OPCODE_PSP_POST_SAVEDATA_SHUTDOWNSTART:
			return sys_psp_post_savedata_shutdownstart();
		break;

		//--------------------------
		// MAP PATHS
		//--------------------------
		case SYSCALL8_OPCODE_MAP_PATHS:
			return sys_map_paths((char **)param1, (char **)param2, (unsigned int)param3);
		break;

		case SYSCALL8_OPCODE_AIO_COPY_ROOT:
			return sys_aio_copy_root((char *)param1, (char *)param2);
		break;

		case SYSCALL8_OPCODE_GET_MAP_PATH:
			return get_map_path((unsigned int)param1, (char *)param2, (char *)param3);
		break;

		case SYSCALL8_OPCODE_MAP_PATH_CALLBACK:
			open_path_callback.addr = (void*)MKA(param1);
			open_path_callback.toc = (void *)MKA(param2);
		break;

		//--------------------------
		// PLUGINS
		//--------------------------
		case SYSCALL8_OPCODE_LOAD_VSH_PLUGIN:
			return sys_prx_load_vsh_plugin(param1, (char *)param2, (void *)param3, param4);
		break;

		case SYSCALL8_OPCODE_UNLOAD_VSH_PLUGIN:
			return sys_prx_unload_vsh_plugin(param1);
		break;

		//--------------------------
		// PROCESS
		//--------------------------
		case SYSCALL8_OPCODE_PROC_CREATE_THREAD:
			return ps3mapi_create_process_thread((process_id_t)param1, (thread_t *)param2, (void *)param3, (uint64_t)param4, (int)param5, (size_t)param6, (char *)param7); // TheRouletteBoi
		break;

		//--------------------------
		// ADVANCED POKE (syscall8)
		//--------------------------
// 8.1
		case SYSCALL8_OPCODE_POKE_LV2:
			*(uint64_t *)param1 = param2;
			clear_icache((void *)param1, 8);
			return SUCCEEDED;
		break;
// 8.2
		case SYSCALL8_OPCODE_POKE32_LV2:
			*(uint32_t *)param1 = (uint32_t)param2;
			clear_icache((void *)param1, 4);
			return SUCCEEDED;
		break;

		case SYSCALL8_OPCODE_POKE16_LV2:
			*(uint16_t *)param1 = (uint16_t)param2;
			clear_icache((void *)param1, 2);
			return SUCCEEDED;
		break;

		case SYSCALL8_OPCODE_POKE8_LV2:
			*(uint8_t *)param1 = (uint8_t)param2;
			clear_icache((void *)param1, 1);
			return SUCCEEDED;
		break;

		case SYSCALL8_OPCODE_POKE_LV1:
			lv1_poked(param1, param2);
			return SUCCEEDED;
		break;

		case SYSCALL8_OPCODE_POKE32_LV1:
			lv1_pokew(param1, (uint32_t)param2);
			return SUCCEEDED;
		break;

		case SYSCALL8_OPCODE_POKE16_LV1:
			lv1_pokeh(param1, (uint16_t)param2);
			return SUCCEEDED;
		break;

		case SYSCALL8_OPCODE_POKE8_LV1:
			lv1_pokeb(param1, (uint8_t)param2);
			return SUCCEEDED;
		break;

		//--------------------------
		// MISC
		//--------------------------
		case SYSCALL8_OPCODE_DRM_GET_DATA:
			return sys_drm_get_data((void *)param1, param2);
		break;

		case SYSCALL8_OPCODE_SEND_POWEROFF_EVENT:
			return sys_sm_ext_send_poweroff_event((int)param1);
		break;

		case SYSCALL8_OPCODE_DISABLE_COBRA_STAGE:
			return disable_cobra_stage();
		break;

		case SYSCALL8_OPCODE_VSH_SPOOF_VERSION:
			return ENOSYS; //sys_vsh_spoof_version((char *)param1);
		break;

		case SYSCALL8_OPCODE_COBRA_USB_COMMAND:
			//return sys_cobra_usb_command(param1, param2, param3, (void *)param4, param5);
			return 0;
		break;

#ifdef DEBUG
		case SYSCALL8_OPCODE_DUMP_STACK_TRACE:
			dump_stack_trace3((void *)param1, 16);
			return SUCCEEDED;
		break;

		case SYSCALL8_OPCODE_PSP_SONY_BUG:
			return sys_psp_sony_bug((uint32_t *)param1, (void *)param2, param3);
		break;

		/*case SYSCALL8_OPCODE_GENERIC_DEBUG:
			return sys_generic_debug(param1, (uint32_t *)param2, (void *)param3);
		break;*/
#endif

		default:
			if (1 <= ps3mapi_partial_disable_syscall8)	return ENOSYS;

			if (extended_syscall8.addr)
			{
				// Lets handle a few hermes opcodes ourself, and let their payload handle the rest
				if (function == 2)
					return (uint64_t)_sys_cfw_memcpy((void *)param1, (void *)param2, param3);
				else if (function == 0xC)
				{
					//DPRINTF("Hermes copy inst: %lx %lx %lx\n", param1, param2, param3);
				}
				else if (function == 0xD)
				{
					//DPRINTF("Hermes poke inst: %lx %lx\n", param1, param2);

					_sys_cfw_new_poke((void *)param1, param2);
					return param1;
				}

				int64_t (* syscall8_hb)() = (void *)&extended_syscall8;

				//DPRINTF("Handling control to HB syscall 8 (opcode=0x%lx)\n", function);
				return syscall8_hb(function, param1, param2, param3, param4, param5, param6, param7);
			}
			else // if (function >= 0x9800) // AV: allow peek all other addresses
			{
				// Partial support for lv1_peek here
				return lv1_peekd(function);
			}
	}

	DPRINTF("Unsupported syscall8 opcode: 0x%lx\n", function);
	return ENOSYS;
}

extern uint8_t auto_dev_blind;	// homebrew_blocker.h
extern uint8_t allow_create_sc; // homebrew_blocker.h
extern uint8_t photo_gui;		// mappath.c

void create_syscalls(void)
{
	create_syscall2(8, syscall8);
	create_syscall2(6, sys_cfw_peek);
	create_syscall2(7, sys_cfw_poke);
	create_syscall2(9, sys_cfw_lv1_poke);
	create_syscall2(10, sys_cfw_lv1_call);
	create_syscall2(11, sys_cfw_lv1_peek);
	create_syscall2(15, sys_cfw_lv2_func);
	#ifdef FAN_CONTROL
	create_syscall2(389, sm_set_fan_policy_sc);
	create_syscall2(409, sm_get_fan_policy_sc);
	#endif
}

int main(void)
{
#ifdef DEBUG
	debug_init();
	debug_install();
	extern uint64_t _start;
	extern uint64_t __self_end;
	DPRINTF("Stage 2 says hello (load base = %p, end = %p) (version = %08X)\n", &_start, &__self_end, MAKE_VERSION(COBRA_VERSION, FIRMWARE_VERSION, IS_CFW));
#endif

	ecdsa_set_curve();
	ecdsa_set_pub();

	vsh_process = get_vsh_process(); //NzV
	if(vsh_process) get_vsh_offset();
	storage_ext_init();
	modules_patch_init();
	drm_init();

	apply_kernel_patches();
	map_path_patches(1);
	storage_ext_patches();
	region_patches();
	permissions_patches();

	#ifdef DO_PATCH_PS2
	ps2_vsh_patches();
	#endif

	// find lv2 on lv1
	for(uint8_t lv2_offset = 1; lv2_offset < 0x10; lv2_offset++)
	{
		LV2_OFFSET_ON_LV1 = (uint64_t)lv2_offset * 0x1000000ULL;
		if(lv1_peekd(LV2_OFFSET_ON_LV1 + 0x3000ULL) == MKA(TOC)) break;
	}

	create_syscalls();

#ifdef DEBUG
	// "Laboratory"
	//do_hook_all_syscalls();
	//do_dump_threads_info_test();
	//do_dump_processes_test();
	//do_hook_load_module();
	//do_hook_mutex_create();
	//do_ps2net_copy_test();
	//do_dump_modules_info_test();
	//do_pad_test();
#endif

	map_path("/app_home", "/dev_usb000", 0); //Not needed

	return 0;
}
