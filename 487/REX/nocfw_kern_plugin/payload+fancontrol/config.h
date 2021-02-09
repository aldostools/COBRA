#ifndef __CONFIG_H__
#define __CONFIG_H__

#define MAX_SPOOF_VERSION			0x0999
#define MAX_SPOOF_REVISION			99999
#define MAX_SPOOF_REVISION_CHARS	5

typedef struct
{
	uint16_t size;
	uint16_t checksum;
	uint8_t bd_video_region;
	uint8_t dvd_video_region;
	uint8_t ps2softemu;
	uint32_t spoof_version;
	uint32_t spoof_revision;
	uint8_t fan_speed;			// 0 = Disabled, 1 = SYSCON, 2 = Dynamic Fan Controller, 0x33 to 0xFF = Set manual fan speed
	uint8_t auto_dev_blind;		// 0 = Allow auto-mount /dev_blind   | 1 = Does not allow auto-mount /dev_blind
	uint8_t allow_restore_sc;	// 0 = Allow to restore CFW syscalls | 1 = Does not allow to restore CFW syscalls
	uint8_t photo_gui;			// 0 = Allow Photo GUI               | 1 = Does not allow Photo GUI
	uint8_t auto_earth;			// 0 = Allow auto-map earth.qrc      | 1 = Does not allow auto-map earth.qrc
} __attribute__((packed)) CobraConfig;

extern CobraConfig config;

int read_cobra_config(void);

#endif /* __CONFIG_H__ */


