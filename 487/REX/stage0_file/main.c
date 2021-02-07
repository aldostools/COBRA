#include <lv2/lv2.h>
#include <lv2/memory.h>
#include <lv2/io.h>
#include <lv2/libc.h>
#include <lv2/thread.h>
#include <lv2/patch.h>
#include <lv1/lv1.h>

// NOTE: stage0 payload size cannot exceed 0x5A8 (1448 bytes)

#if defined (FIRMWARE_4_84) || defined (FIRMWARE_4_85) || defined (FIRMWARE_4_86) || defined (FIRMWARE_4_87)
	#define STAGE2_FILE			"/dev_flash/rebug/cobra/stage2.cex"
	#define STAGE2_FAIL			"/dev_blind/rebug/cobra/stage2.cex"
	#define STAGE2_BIN_SIZE		96104
#elif defined (FIRMWARE_4_84DEX) || defined (FIRMWARE_4_85DEX) || defined (FIRMWARE_4_86DEX) || defined (FIRMWARE_4_87DEX)
	#define STAGE2_FILE			"/dev_flash/rebug/cobra/stage2.dex"
	#define STAGE2_FAIL			"/dev_blind/rebug/cobra/stage2.dex"
	#define STAGE2_BIN_SIZE		96072
#endif

#define WFLASH_MOUNT_POINT		"/dev_blind"
#define STAGE2_FAILSAFE			"/dev_flash/rebug/cobra/failsafe"

#define FAILED					-1

static int disable_cobra_stage2(void)
{
	if(cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", WFLASH_MOUNT_POINT, 0, 0, 0, 0, 0) == CELL_FS_SUCCEEDED)
	{
		return cellFsRename(STAGE2_FAIL, STAGE2_FAIL ".bak");
		//cellFsUtilUmount(WFLASH_MOUNT_POINT, 0, 0); // /dev_blind is unmounted in stage2
	}
	return FAILED;
}

void main(void)
{
	void *stage2 = NULL;

	f_desc_t f;
	int (* func)(void);

	CellFsStat stat;
	int fd;
	uint64_t rs;
	uint32_t payload_size = 0;

	for (int i = 0; i < 128; i++)
	{
		uint64_t pte0 = *(uint64_t *)(MKA(0xf000000 | (i<<7)));
		uint64_t pte1 = *(uint64_t *)(MKA(0xf000008 | (i<<7)));

		lv1_write_htab_entry(0, i << 3, pte0, (pte1 & 0xff0000) | 0x190);
	}

	if (cellFsStat(STAGE2_FILE, &stat) == CELL_FS_SUCCEEDED)
	{
		if (cellFsOpen(STAGE2_FILE, CELL_FS_O_RDONLY, &fd, 0, NULL, 0) == CELL_FS_SUCCEEDED)
		{
			payload_size = stat.st_size;

			stage2 = alloc(payload_size, 0x27);
			if (stage2)
			{
				if (cellFsRead(fd, stage2, payload_size, &rs) != CELL_FS_SUCCEEDED)
				{
					dealloc(stage2, 0x27);
					stage2 = NULL;
				}
			}

			cellFsClose(fd);
		}
	}

	f.toc  = (void *)MKA(TOC);
	f.addr = (void *)MKA(0x17e0);

	if (stage2)
	{
		#if 1
		// "failsafe" must be created by devs to force failsafe
		// This increases the failsafe protection in case a modded stage2 has the same size of the original
		if (cellFsStat(STAGE2_FAILSAFE, &stat) == CELL_FS_SUCCEEDED)
		{
			payload_size = 0;
		}
		if(payload_size != STAGE2_BIN_SIZE)
		{
			// stage2 failsafe by bguerville / AV
			if(disable_cobra_stage2() == CELL_FS_SUCCEEDED) f.addr = stage2;
		}
		else
			f.addr = stage2;
		#else
		// stage2 failsafe by bguerville / AV
		if(disable_cobra_stage2() == CELL_FS_SUCCEEDED) f.addr = stage2;
		#endif
	}

	func = (void *)&f;
	func();
}
