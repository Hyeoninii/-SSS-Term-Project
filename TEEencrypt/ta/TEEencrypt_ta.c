#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <TEEencrypt_ta.h>
#include <string.h>

#define ROOT_KEY 5

static uint8_t random_key;
static TEE_ObjectHandle rsa_keypair = TEE_HANDLE_NULL;

TEE_Result TA_CreateEntryPoint(void) {
	DMSG("TA Create Entry Point has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
	DMSG("TA Destroy Entry Point has been called");
    if (rsa_keypair != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(rsa_keypair);
}

//Session Management
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param __maybe_unused params[4], void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Session Created Successfully\n");

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	IMSG("Session Closed\n");
}

//Caeser Cipher
static TEE_Result generate_random_key()
{
    	TEE_GenerateRandom(&random_key, sizeof(random_key));
	random_key = (random_key % 25) + 1;
	return TEE_SUCCESS;
}

static TEE_Result encrypt_caeser(uint32_t param_types, TEE_Param params[4])
{
    char *text = (char *)params[0].memref.buffer;
    size_t text_len = params[0].memref.size;

    if (!text || text_len == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    DMSG("Encrypting text...");
    DMSG("Plaintext: %s", text);
	for (size_t i = 0; i < text_len; i++) {
        	if (text[i] >= 'a' && text[i] <= 'z') {
            		text[i] = ((text[i] - 'a' + random_key) % 26) + 'a';
        	} else if (text[i] >= 'A' && text[i] <= 'Z') {
            		text[i] = ((text[i] - 'A' + random_key) % 26) + 'A';
        	}
    	}

    uint8_t encrypted_key = (random_key + ROOT_KEY) % 26;
    params[1].value.a = encrypted_key;

    DMSG("Ciphertext: %s", text);
    DMSG("Encrypted Key: %d", encrypted_key);
    return TEE_SUCCESS;
}

static TEE_Result decrypt_caeser(uint32_t param_types, TEE_Param params[4])
{
    char *text = (char *)params[0].memref.buffer;
    size_t text_len = params[0].memref.size;
    uint8_t encrypted_key = params[1].value.a;

    if (!text || text_len == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    uint8_t decryption_key = (encrypted_key + 26 - ROOT_KEY) % 26;

    DMSG("Decrypting text...");
    DMSG("Ciphertext: %s", text);
	
	for (size_t i = 0; i < text_len; i++) {
        if (text[i] >= 'a' && text[i] <= 'z') {
            text[i] = ((text[i] - 'a' + 26 - decryption_key) % 26) + 'a';
        } else if (text[i] >= 'A' && text[i] <= 'Z') {
            text[i] = ((text[i] - 'A' + 26 - decryption_key) % 26) + 'A';
        }
    }

    DMSG("Plaintext: %s", text);
    return TEE_SUCCESS;
}

//RSA Cipher
static TEE_Result generate_rsa_keypair()
{
    TEE_Result res;
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 2048, &rsa_keypair);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_GenerateKey(rsa_keypair, 2048, NULL, 0);
    return res;
}

static TEE_Result encrypt_rsa(uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    char *plaintext = (char *)params[0].memref.buffer;
    size_t plaintext_len = params[0].memref.size;
    char ciphertext[256] = {0};
    size_t ciphertext_len = sizeof(ciphertext);

    TEE_OperationHandle op;
    res = TEE_AllocateOperation(&op, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, 2048);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_SetOperationKey(op, rsa_keypair);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_AsymmetricEncrypt(op, NULL, 0, plaintext, plaintext_len, ciphertext, &ciphertext_len);
    if (res != TEE_SUCCESS)
        return res;

    memcpy(params[0].memref.buffer, ciphertext, ciphertext_len);
    params[0].memref.size = ciphertext_len;

    TEE_FreeOperation(op);
    return TEE_SUCCESS;
}



TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4])
{
    switch (cmd_id) {
    case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
        generate_random_key();
        return encrypt_caeser(param_types, params);
    case TA_TEEencrypt_CMD_RANDOMKEY_DEC:
        return decrypt_caeser(param_types, params);
    case TA_TEEencrypt_CMD_RSAKEY_ENC:
        if (rsa_keypair == TEE_HANDLE_NULL)
            generate_rsa_keypair();
        return encrypt_rsa(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
