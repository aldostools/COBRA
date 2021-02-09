#include <lv2/lv2.h>
#include <lv2/error.h>
#include <lv2/libc.h>
#include <lv2/io.h>
#include <lv2/memory.h>
#include "config.h"

#define COBRA_CONFIG_FILE	"/dev_hdd0/vm/cobra_cfg.bin"

CobraConfig config;

#ifdef FAN_CONTROL
extern uint8_t set_fan_speed;		// fan_control.h
#endif

void load_fan_control(void);

int read_cobra_config(void)
{
	memset(&config, 0, sizeof(config));

	int fd;
	if (cellFsOpen(COBRA_CONFIG_FILE, CELL_FS_O_RDONLY, &fd, 0, NULL, 0) == CELL_FS_SUCCEEDED)
	{
		size_t read;
		cellFsRead(fd, &config, sizeof(config), &read);
		cellFsClose(fd);
	}

	config.size = sizeof(config);

	#ifdef FAN_CONTROL
	set_fan_speed    = config.fan_speed;			// 0 = DISABLED, 1 = SYSCON, 2 = Dynamic Fan Controller, 0x33 to 0xFF = Set manual fan speed
	load_fan_control();
	#endif

	return SUCCEEDED;
}
