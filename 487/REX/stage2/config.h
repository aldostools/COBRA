#ifndef __CONFIG_H__
#define __CONFIG_H__

#define MAX_SPOOF_VERSION			0x0999
#define MAX_SPOOF_REVISION			99999
#define MAX_SPOOF_REVISION_CHARS	5

typedef struct
{
	uint16_t size; // size of structure, this will be set automatically by the library
	uint16_t checksum; // Only for core, don't mess with this
	uint8_t bd_video_region; // One of BDRegion, or 0 for default
	uint8_t dvd_video_region; // One of DVDRegion or 0 for default
	uint8_t ps2softemu; // Non-zero to show ps2 discs in non bc consoles
	uint32_t spoof_version; // version in BCD, eg. 0x0484, Max value: 0x0999 // feature is unavailable (use SEN Enabler for version spoofer)
	uint32_t spoof_revision; // revision number (decimal), MAx value: 99999 // feature is unavailable (use SEN Enabler for version spoofer)
	uint8_t fan_speed;			// 0 = Disabled, 1 = SYSCON, 2 = Dynamic Fan Controller, 0x33 to 0xFF = Set manual fan speed
	uint8_t allow_restore_sc;	// 1 = Allow to restore CFW syscalls | 0 = Does not allow to restore CFW syscalls
	uint8_t skip_existing_rif;	// 1 = Skip if .rif already exists   | 0 = Does not skip if .rif already exists
	uint8_t photo_gui;			// 1 = Allow Photo GUI               | 0 = Does not allow Photo GUI
	uint8_t auto_earth;			// 1 = Allow auto-map earth.qrc      | 0 = Does not allow auto-map earth.qrc
	uint8_t auto_dev_blind;		// 1 = Allow auto-mount /dev_blind   | 0 = Does not allow auto-mount /dev_blind
} __attribute__((packed)) CobraConfig;

extern CobraConfig config;

int read_cobra_config(void);

// Syscalls
int sys_read_cobra_config(CobraConfig *cfg);
int sys_write_cobra_config(CobraConfig *cfg);

#endif /* __CONFIG_H__ */


