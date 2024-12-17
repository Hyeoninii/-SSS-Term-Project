#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <TEEencrypt_ta.h>
#include <string.h>

#define ROOT_KEY 5
#define RSA_KEY_SIZE 1024
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

static uint8_t random_key;

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
    case TA_TEEencrypt_CMD_RSA_GEN:
        return RSA_create_key_pair(session);
    case TA_TEEencrypt_CMD_RSA_ENC:
        return RSA_encrypt(session, param_types, params);
    case TA_TEEencrypt_CMD_RSA_DEC:
        return RSA_decrypt(session, param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

//RSA key generate, encrypt, decrypt

TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char *) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);					
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}

TEE_Result RSA_decrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[1].memref.buffer;
	size_t plain_len = params[1].memref.size;
	void *cipher = params[0].memref.buffer;
	size_t cipher_len = params[0].memref.size;

	DMSG("\n========== Preparing decryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_DECRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to decrypt: %s\n", (char *) cipher);
	ret = TEE_AsymmetricDecrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
				cipher, cipher_len, plain_txt, &plain_len);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to decrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nDecrypted data: %s\n", (char *) plain_txt);
	DMSG("\n========== Decryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeTransientObject(sess->key_handle);
	return ret;
}