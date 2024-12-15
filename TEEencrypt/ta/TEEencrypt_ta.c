#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <TEEencrypt_ta.h>
#include <string.h>

#define ROOT_KEY 5
#define RSA_KEY_SIZE 2048  // RSA 키 크기
#define RSA_BUFFER_SIZE 256
static uint8_t random_key;


static TEE_ObjectHandle rsa_keypair = TEE_HANDLE_NULL;  // RSA 키 저장소

// RSA 키 생성
static TEE_Result generate_rsa_keypair(void) {
    TEE_Result res;
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_KEY_SIZE, &rsa_keypair);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate RSA keypair: 0x%x", res);
        return res;
    }

    res = TEE_GenerateKey(rsa_keypair, RSA_KEY_SIZE, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to generate RSA keypair: 0x%x", res);
        TEE_FreeTransientObject(rsa_keypair);
        rsa_keypair = TEE_HANDLE_NULL;
        return res;
    }

    IMSG("RSA keypair generated successfully");
    return TEE_SUCCESS;
}

static TEE_Result rsa_encrypt(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    void *plaintext = params[0].memref.buffer;
    size_t plaintext_len = params[0].memref.size;

    void *ciphertext = params[1].memref.buffer;
    size_t ciphertext_len = params[1].memref.size;

    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_RSA_MODULUS, NULL, 0);  // 사용하지 않음

    TEE_Result res = TEE_AsymmetricEncrypt(rsa_keypair, NULL, 0, plaintext,
                                           plaintext_len, ciphertext, &ciphertext_len);
    if (res != TEE_SUCCESS) {
        EMSG("RSA encryption failed: 0x%x", res);
        return res;
    }

    params[1].memref.size = ciphertext_len;
    IMSG("RSA encryption successful");
    return TEE_SUCCESS;
}

static TEE_Result rsa_decrypt(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    void *ciphertext = params[0].memref.buffer;
    size_t ciphertext_len = params[0].memref.size;

    void *plaintext = params[1].memref.buffer;
    size_t plaintext_len = params[1].memref.size;

    TEE_Result res = TEE_AsymmetricDecrypt(rsa_keypair, NULL, 0, ciphertext,
                                           ciphertext_len, plaintext, &plaintext_len);
    if (res != TEE_SUCCESS) {
        EMSG("RSA decryption failed: 0x%x", res);
        return res;
    }

    params[1].memref.size = plaintext_len;
    IMSG("RSA decryption successful");
    return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void) {
	DMSG("TA Create Entry Point has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
	DMSG("TA Destroy Entry Point has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Session Created Successfully\n");

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	IMSG("Session Closed\n");
}

static TEE_Result generate_random_key()
{
    	TEE_GenerateRandom(&random_key, sizeof(random_key));
	random_key = (random_key % 25) + 1;
	return TEE_SUCCESS;
}

static TEE_Result encrypt_text(uint32_t param_types, TEE_Param params[4])
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

static TEE_Result decrypt_text(uint32_t param_types, TEE_Param params[4])
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

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4])
{
    switch (cmd_id) {
    case TA_TEEencrypt_CMD_ENC_VALUE:
        generate_random_key();
        return encrypt_text(param_types, params);
    case TA_TEEencrypt_CMD_DEC_VALUE:
        return decrypt_text(param_types, params);
    case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
        generate_random_key();
        return encrypt_text(param_types, params);
    case TA_TEEencrypt_CMD_RSA_KEY_ENC:
        return rsa_encrypt(param_types, params);
    case TA_TEEencrypt_CMD_RANDOMKEY_GET:
        params[0].value.a = random_key;
        return TEE_SUCCESS;
    case TA_TEEencrypt_CMD_RSA_KEY_GET:
        return get_rsa_public_key(param_types, params);
    case TA_TEEencrypt_CMD_RANDOMKEY_DEC:
        return decrypt_text(param_types, params);
    case TA_TEEencrypt_CMD_RSA_KEY_DEC:
        return rsa_decrypt(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
