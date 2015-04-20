#ifndef _LiTo_H_
#define _LiTo_H_


#define B_NONE		0x00
#define B_MODRM		0x01
#define B_DATA8		0x02
#define B_DATA16	0x04
#define B_RELX		0x08
#define B_PREFIX6X	0x10

#ifdef __cplusplus
extern "C" {
#endif

/*extern "C"*/ int __stdcall LiTo(unsigned char *pCode,char *relok);

#ifdef __cplusplus
}
#endif

#endif /* _LiTo_H_*/


