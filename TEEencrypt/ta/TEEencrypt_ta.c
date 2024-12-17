#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <TEEencrypt_ta.h>
#include <string.h>

#define ROOT_KEY 5
#define RSA_KEY_SIZE 2048

static uint8_t random_key;

struct rsa_session {
    TEE_OperationHandle op_handle;  /* RSA operation handle */
    TEE_ObjectHandle key_handle;    /* RSA key handle */
};


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
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
                                    TEE_Param __unused params[4],
                                    void **sess_ctx) {
    struct rsa_session *sess = TEE_Malloc(sizeof(*sess), 0);
    if (!sess)
        return TEE_ERROR_OUT_OF_MEMORY;

    sess->key_handle = TEE_HANDLE_NULL;
    sess->op_handle = TEE_HANDLE_NULL;
    *sess_ctx = (void *)sess;

    IMSG("Session Created Successfully\n");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    struct rsa_session *sess = (struct rsa_session *)sess_ctx;

    if (sess->key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(sess->key_handle);
    if (sess->op_handle != TEE_HANDLE_NULL)
        TEE_FreeOperation(sess->op_handle);

    TEE_Free(sess);
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
static TEE_Result create_rsa_keypair(struct rsa_session *sess) {
    return TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_KEY_SIZE, &sess->key_handle) ||
           TEE_GenerateKey(sess->key_handle, RSA_KEY_SIZE, NULL, 0);
}

static TEE_Result encrypt_rsa(struct rsa_session *sess, uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    void *plain = params[0].memref.buffer;
    size_t plain_len = params[0].memref.size;
    void *cipher = params[1].memref.buffer;
    size_t cipher_len = params[1].memref.size;

    if (cipher_len < (RSA_KEY_SIZE / 8)) {
        EMSG("Output buffer too small for RSA encryption");
        return TEE_ERROR_SHORT_BUFFER;
    }

    res = TEE_AllocateOperation(&sess->op_handle, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, RSA_KEY_SIZE);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate RSA operation: 0x%x", res);
        return res;
    }

    res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to set RSA key: 0x%x", res);
        TEE_FreeOperation(sess->op_handle);
        return res;
    }

    res = TEE_AsymmetricEncrypt(sess->op_handle, NULL, 0, plain, plain_len, cipher, &cipher_len);
    if (res != TEE_SUCCESS) {
        EMSG("RSA encryption failed: 0x%x", res);
    } else {
        params[1].memref.size = cipher_len;
        DMSG("RSA encryption successful.");
    }

    TEE_FreeOperation(sess->op_handle);
    return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
    struct rsa_session *sess = (struct rsa_session *)sess_ctx;

    switch (cmd_id) {
    case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
        generate_random_key();
        return encrypt_caeser(param_types, params);
    case TA_TEEencrypt_CMD_RANDOMKEY_DEC:
        return decrypt_caeser(param_types, params);
    case TA_TEEencrypt_CMD_RSAKEY_ENC:
        if (sess->key_handle == TEE_HANDLE_NULL) {
            TEE_Result res = create_rsa_keypair(sess);
            if (res != TEE_SUCCESS) {
                EMSG("Failed to create RSA keypair: 0x%x", res);
                return res;
            }
            DMSG("RSA keypair created successfully.");
        }
        return encrypt_rsa(sess, param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
