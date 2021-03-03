#include <lv2/libc.h>
#include <lv2/io.h>
#include <lv2/error.h>
#include <lv2/security.h>
#include "common.h"
#include "mappath.h"
#include "modulespatch.h"
#include "ps3mapi_core.h"
#include "make_rif.h"

uint8_t skip_existing_rif = 0;

static unsigned char RAP_KEY[] =  { 0x86, 0x9F, 0x77, 0x45, 0xC1, 0x3F, 0xD8, 0x90, 0xCC, 0xF2, 0x91, 0x88, 0xE3, 0xCC, 0x3E, 0xDF };
static unsigned char RAP_PBOX[] = { 0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09 };
static unsigned char RAP_E1[] =   { 0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29, 0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5 };
static unsigned char RAP_E2[] =   { 0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A, 0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74 };

static uint8_t make_rif_buf[0x20 + 0x28 + 0x50 + 0x20 + 0x28]; // ACT_DAT[0x20] + CONTENT_ID[0x28] + RAP_PATH[0x50] + RIF_BUFFER[0x20] (rif_buffer reuse rap_path + 0x20 = 0x70)+0x28(signaturs)

static void aescbc128_decrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len)
{
	aescbccfb_dec(out, in, len, key, 128, iv);

	// Reset the IV.
	memset(iv, 0, 0x10);
}

static void get_rif_key(unsigned char* rap, unsigned char* rif)
{
	int i;
	int round;

	unsigned char key[0x10];
	unsigned char iv[0x10];
	memset(key, 0, 0x10);
	memset(iv, 0, 0x10);

	// Initial decrypt.
	aescbc128_decrypt(RAP_KEY, iv, rap, key, 0x10);

	// rap2rifkey round.
	for (round = 0; round < 5; ++round)
	{
		for (i = 0; i < 16; ++i)
		{
			int p = RAP_PBOX[i];
			key[p] ^= RAP_E1[p];
		}

		for (i = 15; i >= 1; --i)
		{
			int p = RAP_PBOX[i];
			int pp = RAP_PBOX[i - 1];
			key[p] ^= key[pp];
		}

		int o = 0;

		for (i = 0; i < 16; ++i)
		{
			int p = RAP_PBOX[i];
			unsigned char kc = key[p] - o;
			unsigned char ec2 = RAP_E2[p];
			if (o != 1 || kc != 0xFF)
			{
				o = kc < ec2 ? 1 : 0;
				key[p] = kc - ec2;
			}
			else if (kc == 0xFF)
				key[p] = kc - ec2;
			else
				key[p] = kc;
		}
	}

	memcpy(rif, key, 0x10);
}

static void read_act_dat_and_make_rif(uint8_t *rap, uint8_t *act_dat, const char *content_id, const char *rif_path)
{
	int fd;

	if(cellFsOpen(rif_path, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &fd, 0666, NULL, 0) == SUCCEEDED)
	{
		uint8_t idps_const[0x10]    = {0x5E, 0x06, 0xE0, 0x4F, 0xD9, 0x4A, 0x71, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
		uint8_t rif_key_const[0x10] = {0xDA, 0x7D, 0x4B, 0x5E, 0x49, 0x9A, 0x4F, 0x53, 0xB1, 0xC1, 0xA1, 0x4A, 0x74, 0x84, 0x44, 0x3B};

		uint8_t *rif = ALLOC_RIF_BUFFER;
		uint8_t *key_index = rif + 0x40;
		uint8_t *rif_key   = rif + 0x50;
		memset(rif, 0, 0x70);

		get_rif_key(rap, rif_key); //convert rap to rifkey (klicensee)

		uint8_t *iv = rif + 0x60;
		//memset(iv, 0, 0x10); // already done
		aescbccfb_enc(idps_const, idps_const, 0x10, (void*)PS3MAPI_IDPS_2, IDPS_KEYBITS, iv);

		uint8_t *act_dat_key = rap;
		memcpy(act_dat_key, act_dat + 0x10, 0x10);

		memset(iv, 0, 0x10);
		aescbccfb_dec(act_dat_key, act_dat_key, 0x10, idps_const, IDPS_KEYBITS, iv);

		memset(iv, 0, 0x10);
		aescbccfb_enc(rif_key, rif_key, 0x10, act_dat_key, ACT_DAT_KEYBITS, iv);

		memset(iv, 0, 0x10);
		aescbccfb_enc(key_index, key_index, 0x10, rif_key_const, RIF_KEYBITS, iv);

		const uint32_t version_number = 1;
		const uint32_t license_type = 0x00010002;
		const uint64_t timestamp = 0x000001619BF6DDCA;
		const uint64_t expiration_time = 0;

		memcpy(rif,        &version_number,  4); // 0x00 version_number
		memcpy(rif + 0x04, &license_type,    4); // 0x04 license_type
		memcpy(rif + 0x08, act_dat + 0x8,    8); // 0x08 account_id
		memcpy(rif + 0x10, content_id,    0x24); // 0x10 content_id
												 // 0x40 encrypted key index (Used for choosing act.dat key)
												 // 0x50 encrypted rif_key
		memcpy(rif + 0x60, &timestamp,       8); // 0x60 timestamp
		memcpy(rif + 0x68, &expiration_time, 8); // 0x68 expiration time

		uint64_t size;
		memset(rif + 0x70, 0x11, 0x28);			 // 0x70 ECDSA Signature
		cellFsWrite(fd, rif, 0x98, &size);
		cellFsClose(fd);
	}
}

void make_rif(const char *path)
{
	int path_len = strlen(path);
	if(!strncmp(path, "/dev_hdd0/home/", 15) && !strcmp(path + path_len - 4, ".rif"))
	{
		// Skip the creation of rif if already exists - By aldostool's
		CellFsStat stat;
		if(skip_existing_rif && (cellFsStat(path, &stat) == SUCCEEDED))
		{
			#ifdef DEBUG
				DPRINTF("rif already exists, skipping...\n");
			#endif

			return; // rif already exists
		}

		#ifdef DEBUG
			DPRINTF("open_path_hook: %s (looking for rap)\n", path);
		#endif

		char *content_id = ALLOC_CONTENT_ID;
		memset(content_id, 0, 0x25);
		strncpy(content_id, strrchr(path, '/') + 1, 0x24);

		char *rap_path = ALLOC_PATH_BUFFER;

		uint8_t is_ps2_classic = !strncmp(content_id, "2P0001-PS2U10000_00-0000111122223333", 0x24);

		if(!is_ps2_classic)
		{
			const char *ext = ".rap";
			for(uint8_t i = 0; i < 2; i++)
			{
				sprintf(rap_path, "/dev_usb000/exdata/%.36s%s", content_id, ext);
				if(cellFsStat(rap_path, &stat)) {rap_path[10] = '1'; //usb001
				if(cellFsStat(rap_path, &stat)) sprintf(rap_path, "/dev_hdd0/exdata/%.36s%s", content_id, ext);}
				if(cellFsStat(rap_path, &stat)) ext = ".RAP"; else break;
			}
		}

		int fd;
		if(is_ps2_classic || cellFsOpen(rap_path, CELL_FS_O_RDONLY, &fd, 0666, NULL, 0) == SUCCEEDED)
		{
			uint64_t nread = 0;
			uint8_t rap[0x10] = {0xF5, 0xDE, 0xCA, 0xBB, 0x09, 0x88, 0x4F, 0xF4, 0x02, 0xD4, 0x12, 0x3C, 0x25, 0x01, 0x71, 0xD9};

			if(!is_ps2_classic)
			{
				cellFsRead(fd, rap, 0x10, &nread);
				cellFsClose(fd);
			}

			#ifdef DEBUG
				DPRINTF("rap_path:%s output:%s\n", rap_path, path);
			#endif

			char *act_path = ALLOC_PATH_BUFFER;
			memset(act_path, 0, 0x50);
			strncpy(act_path, path, strrchr(path, '/') - path);
			strcpy(act_path + strlen(act_path), "/act.dat\0");

			#ifdef DEBUG
				DPRINTF("act_path:%s content_id:%s\n", act_path, content_id);
			#endif

			if(cellFsOpen(act_path, CELL_FS_O_RDONLY, &fd, 0666, NULL, 0) == SUCCEEDED)
			{
				uint8_t *act_dat = ALLOC_ACT_DAT;
				cellFsRead(fd, act_dat, 0x20, &nread); // size: 0x1038 but only first 0x20 are used to make rif
				cellFsClose(fd);

				if(nread == 0x20)
				{
					char *rif_path = ALLOC_PATH_BUFFER;
					sprintf(rif_path, "/%s", path);
					read_act_dat_and_make_rif(rap, act_dat, content_id, rif_path);

					#ifdef DEBUG
						DPRINTF("rif_path:%s\n", rif_path);
					#endif
				}
			}
			else
			{
				#ifdef DEBUG
					DPRINTF("act.dat not found: %s\n", act_path);
				#endif
			}
		}
	}
}
