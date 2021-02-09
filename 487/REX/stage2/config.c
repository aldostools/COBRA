#include <lv2/lv2.h>
#include <lv2/error.h>
#include <lv2/libc.h>
#include <lv2/io.h>
#include <lv2/memory.h>
#include "common.h"
#include "config.h"
#include "region.h"
#include "storage_ext.h"
#include "modulespatch.h"

#define COBRA_CONFIG_FILE	"/dev_hdd0/vm/cobra_cfg.bin"

CobraConfig config;

#ifdef FAN_CONTROL
extern uint8_t set_fan_speed;		// fan_control.h
#endif
#ifdef DO_AUTO_MOUNT_DEV_BLIND
extern uint8_t auto_dev_blind;		// homebrew_blocker.h
#endif
#ifdef DO_AUTO_RESTORE_SC
extern uint8_t allow_restore_sc;	// homebrew_blocker.h
#endif
#ifdef DO_PHOTO_GUI
extern uint8_t photo_gui;			// mappath.c
#endif
#ifdef DO_AUTO_EARTH
extern uint8_t auto_earth;			// mappath.c
#endif

void load_fan_control(void);

static void check_and_correct(CobraConfig *cfg)
{
	int found = 0;

	int i;
	for (i = 1; i <= BD_VIDEO_REGION_MAX; i *= 2)
	{
		if (cfg->bd_video_region == i)
		{
			found = 1;
			break;
		}
	}

	if (!found)
		cfg->bd_video_region = 0;
	else
		found = 0;

	for (i = 1; i <= DVD_VIDEO_REGION_MAX; i *= 2)
	{
		if (cfg->dvd_video_region == i)
		{
			found = 1;
			break;
		}
	}

	if (!found)
		cfg->dvd_video_region = 0;

	if (cfg->ps2softemu > 1)
		cfg->ps2softemu = 0;

	//if (cfg->spoof_version > MAX_SPOOF_VERSION)
		cfg->spoof_version = 0;
	/*else
	{
		uint8_t h, l;

		h = (cfg->spoof_version&0xFF)>>4;
		l = cfg->spoof_version&0xF;

		if (h > 9 || l > 9)
			cfg->spoof_version = 0;
	}

	if (cfg->spoof_revision > MAX_SPOOF_REVISION)*/
		cfg->spoof_revision = 0;

	if (cfg->size > sizeof(CobraConfig))
		cfg->size = sizeof(CobraConfig);
}
/*
static uint16_t checksum(CobraConfig *cfg)
{
	uint8_t *buf = &cfg->bd_video_region;
	uint16_t size = cfg->size - sizeof(cfg->size) - sizeof(cfg->checksum);
	uint16_t cs = 0;

	for (int i = 0; i < size; i++)
		cs += buf[i];

	return cs;
}
*/
int read_cobra_config(void)
{
	memset(&config, 0, sizeof(config));

	read_file(COBRA_CONFIG_FILE, &config, sizeof(config));


//	if (config.size > 4096 || checksum(&config) != config.checksum)
//		memset(&config, 0, sizeof(config));
//	else
		check_and_correct(&config);

	config.size = sizeof(config);

	bd_video_region = config.bd_video_region;
	dvd_video_region = config.dvd_video_region;

	#ifdef DO_AUTO_MOUNT_DEV_BLIND
	auto_dev_blind   = !config.auto_dev_blind;		// 0 = Allow auto-mount /dev_blind   | 1 = Does not allow auto-mount /dev_blind
	#endif
	#ifdef DO_AUTO_RESTORE_SC
	allow_restore_sc = !config.allow_restore_sc;	// 0 = Allow to restore CFW syscalls | 1 = Does not allow to restore CFW syscalls
	#endif
	#ifdef DO_PHOTO_GUI
	photo_gui        = !config.photo_gui;			// 0 = Allow Photo GUI				 | 1 = Does not allow Photo GUI
	#endif
	#ifdef DO_AUTO_EARTH
	auto_earth       = !config.auto_earth;			// 0 = Allow auto-map earth.qrc      | 1 = Does not allow auto-map earth.qrc
	#endif
	#ifdef FAN_CONTROL
	set_fan_speed    = config.fan_speed;			// 0 = DISABLED, 1 = SYSCON, 2 = Dynamic Fan Controller, 0x33 to 0xFF = Set manual fan speed
	load_fan_control();
	#endif

	// Removed. Now condition_ps2softemu has another meaning and it is set automatically in storage_ext if no BC console
	//condition_ps2softemu = config.ps2softemu;
	#ifdef  DEBUG
		DPRINTF("Configuration read. bd_video_region=%d,dvd_video_region=%d\n",
				bd_video_region, dvd_video_region);
	#endif

	return SUCCEEDED;
}

static int write_cobra_config(void)
{
	return save_file(COBRA_CONFIG_FILE, &config, sizeof(config));
}

int sys_read_cobra_config(CobraConfig *cfg)
{
	//int erase_size, copy_size;

	cfg = get_secure_user_ptr(cfg);

	//if (cfg->size > 4096)
	//	return EINVAL;

/*	erase_size = cfg->size-sizeof(config.size);
	if (erase_size < 0)
		erase_size = 0;

	memset(&cfg->checksum, 0, erase_size);

	copy_size = ((cfg->size > config.size) ? config.size : cfg->size) - sizeof(config.size);
	if (copy_size < 0)
		copy_size = 0;

	#ifdef  DEBUG
		//DPRINTF("erase = %d, copy = %d\n", erase_size, copy_size);
	#endif
*/
	memcpy(&cfg->checksum, &config.checksum, sizeof(CobraConfig));
	return SUCCEEDED;
}

int sys_write_cobra_config(CobraConfig *cfg)
{
	//int copy_size;

	cfg = get_secure_user_ptr(cfg);

	//if (cfg->size > 4096)
	//	return EINVAL;

	memcpy(&config, &cfg, sizeof(config));

	check_and_correct(cfg);

	config.spoof_version  = 0; // deprecated
	config.spoof_revision = 0; // deprecated

/*	cfg->checksum = checksum(cfg);
	copy_size = cfg->size - sizeof(config.size);
	if (copy_size < 0)
		copy_size = 0;

	memcpy(&config.checksum, &cfg->checksum, copy_size);*/
	bd_video_region = config.bd_video_region;
	dvd_video_region = config.dvd_video_region;
	// Removed. Now condition_ps2softemu has another meaning and it is set automatically in storage_ext if no BC console
	//condition_ps2softemu = config.ps2softemu;

	return write_cobra_config();
}
