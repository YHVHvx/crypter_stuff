#ifndef _LiTo32_H_
#define _LiTo32_H_


#define B_NONE		0x00
#define B_MODRM		0x01
#define B_DATA8		0x02
#define B_DATA16	0x04
#define B_RELX		0x08
#define B_PREFIX6X	0x10
#define B_SEG		0x20
#define B_LOCK		0x40
#define B_PFX66		0x80
#define B_PFX67		0x100
#define B_REP		0x200
#define B_OPCODE2	0x400

#define ubyte unsigned char


#ifdef __cplusplus
extern "C" {
#endif

/*extern "C" */int __stdcall _LiTo_(ubyte *pCode,void *outdata);

#ifdef __cplusplus
}
#endif

#endif /*_LiTo32_H_*/