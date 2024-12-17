#ifndef TA_TEEencrypt_H
#define TA_TEEencrypt_H


#define TA_TEEencrypt_UUID \
	{ 0x1d844919, 0x987e, 0x4577, \
		{ 0xa1, 0xd9, 0xc1, 0x73, 0x39, 0x24, 0x2c, 0x7c} }

#define TA_TEEencrypt_CMD_ENC_VALUE			0
#define TA_TEEencrypt_CMD_DEC_VALUE			1
#define TA_TEEencrypt_CMD_RANDOMKEY_GET		2
#define TA_TEEencrypt_CMD_RANDOMKEY_ENC		3
#define TA_TEEencrypt_CMD_RSA_GEN			4
#define TA_TEEencrypt_CMD_RSA_ENC			5
#define TA_TEEencrypt_CMD_RSA_DEC			6


#endif /*TA_TEEencrypt_H*/
