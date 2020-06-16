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

int sm_set_fan_policy(uint8_t arg1, uint8_t arg2, uint8_t arg3);
void do_fan_control(void);
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
	// Removed. Now condition_ps2softemu has another meaning and it is set automatically in storage_ext if no BC console
	//condition_ps2softemu = config.ps2softemu;
	#ifdef  DEBUG
		DPRINTF("Configuration read. bd_video_region=%d,dvd_video_region=%d\n",
				bd_video_region, dvd_video_region);
	#endif

	#ifdef FAN_CONTROL
	if(config.fan_speed >= 0x33 && config.fan_speed <= 0x80)
		sm_set_fan_policy(0, 2, config.fan_speed); // Manual mode
	else if(config.fan_speed <= 1)
		sm_set_fan_policy(0, 1, 0); // SYSCON mode
	else // if(config.fan_speed >= 2 && config.fan_speed <= 0x32)
		do_fan_control();  // Dynamic fan control
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

	if (cfg->size > 4096)
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



