#ifndef __MAKE_RIF_H__
#define __MAKE_RIF_H__

#define IDPS_KEYBITS 	128
#define ACT_DAT_KEYBITS 128
#define RIF_KEYBITS 	128
#define RAP_KEYBITS 	128

//////// make_rif memory allocation ////////////
#define ALLOC_ACT_DAT	 	(uint8_t*)(make_rif_buf)
#define ALLOC_CONTENT_ID	(char*)(make_rif_buf + 0x20)
#define ALLOC_PATH_BUFFER	(char*)(make_rif_buf + 0x20 + 0x28)
#define ALLOC_RIF_BUFFER 	(uint8_t*)(make_rif_buf + 0x20 + 0x28)
////////////////////////////////////////////////

extern uint8_t skip_existing_rif;

//extern unsigned char RAP_KEY[];
//extern unsigned char RAP_PBOX[];
//extern unsigned char RAP_E1[];
//extern unsigned char RAP_E2[];

void make_rif(const char *path);

#endif /* __MAKE_RIF_H__ */
