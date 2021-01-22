#include <lv2/lv2.h>
#include <lv2/memory.h>
#include <lv2/io.h>
#include <lv2/libc.h>
#include <lv2/thread.h>
#include <lv2/patch.h>
#include <lv1/lv1.h>

#define STAGE2_FILE	"/dev_flash/sys/stage2.bin"
#define STAGE2_FAIL	"/dev_blind/sys/stage2.bin"

void main(void)
{
	void *stage2 = NULL;

	f_desc_t f;
	int (* func)(void);

	CellFsStat stat;
	int fd;
	uint64_t rs;

	for (int i = 0; i < 128; i++)
	{
		uint64_t pte0 = *(uint64_t *)(MKA(0xf000000 | (i << 7)));
		uint64_t pte1 = *(uint64_t *)(MKA(0xf000000 | ((i << 7) + 8)));

		lv1_write_htab_entry(0, i << 3, pte0, (pte1 & 0xff0000) | 0x190);
	}

	if (cellFsStat(STAGE2_FILE, &stat) == 0)
	{
		if (cellFsOpen(STAGE2_FILE, CELL_FS_O_RDONLY, &fd, 0, NULL, 0) == 0)
		{
			stage2 = alloc(stat.st_size, 0x27);
			if (stage2)
			{
				if (cellFsRead(fd, stage2, stat.st_size, &rs) != 0)
				{
					dealloc(stage2, 0x27);
					stage2 = NULL;
				}
			}

			cellFsClose(fd);
		}
	}

	f.toc = (void *)MKA(TOC);

	if (stage2)
	{
		// stage2 fail save by bguerville / AV
		cellFsUtilMount_h("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0, 0);
		cellFsRename(STAGE2_FAIL, STAGE2_FAIL ".bak");
		f.addr = stage2;
	}
	else
		f.addr = (void *)MKA(0x17e0);

	func = (void *)&f;
	func();
}
