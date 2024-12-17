#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

#define MAX_TEXT_LEN 1024


//파일 처리 관련 함수
void read_file(const char *filename, char *buffer) {
    FILE *file = fopen(filename, "r");
    if (!file)
        errx(1, "Failed to open %s", filename);
    fread(buffer, 1, MAX_TEXT_LEN, file);
    fclose(file);
}

void write_file(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (!file)
        errx(1, "Failed to write to %s", filename);
    fprintf(file, "%s", data);
    fclose(file);
}


int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: TEEencrypt -e [plaintext file] [caeser or rsa] (encryption)\n");
        printf("       TEEencrypt -d [ciphertext file] [key file] (decryption)\n");
        return 1;
    }

    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", res, err_origin);

    memset(&op, 0, sizeof(op));

    if (strcmp(argv[1], "-e") == 0) {
        char plaintext[MAX_TEXT_LEN] = {0};
        char ciphertext[RSA_KEY_SIZE / 8] = {0};

        read_file(argv[2], plaintext);

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = plaintext;
        op.params[0].tmpref.size = strlen(plaintext) + 1;
        op.params[1].tmpref.buffer = ciphertext;
        op.params[1].tmpref.size = sizeof(ciphertext);


        if (strcmp(argv[3], "caeser") == 0) {
            res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);
            if (res != TEEC_SUCCESS)
                errx(1, "TEEC_InvokeCommand (encrypt) failed 0x%x origin 0x%x", res, err_origin);

                char encrypted_key[16];
                snprintf(encrypted_key, sizeof(encrypted_key), "%d", op.params[1].value.a);
                write_file("caeserkey.txt", encrypted_key);
                printf("Caeser key saved to caeserkey.txt\n");
            }
            } else if (strcmp(argv[3], "rsa") == 0) {
                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSAKEY_ENC, &op, &err_origin);
            } else {
                printf("Wrong Algorithm. Use \"caeser\" or \"rsa\".\n");
                return 1;
            }

            if (res != TEEC_SUCCESS)
                errx(1, "TEEC_InvokeCommand (encrypt) failed 0x%x origin 0x%x", res, err_origin);

            // 암호화된 결과를 바이너리 형태로 파일에 저장
            FILE *out_file = fopen("ciphertext.txt", "wb");
            if (!out_file)
                errx(1, "Failed to write to ciphertext.txt");
            fwrite(ciphertext, 1, op.params[1].tmpref.size, out_file);
            fclose(out_file);

            printf("Encryption complete. Output: ciphertext.txt\n");

    } else if (strcmp(argv[1], "-d") == 0) {
        char ciphertext[RSA_KEY_SIZE / 8] = {0};
        char plaintext[MAX_TEXT_LEN] = {0};

        // 암호문 읽기 (바이너리 데이터)
        FILE *in_file = fopen(argv[2], "rb");
        if (!in_file)
            errx(1, "Failed to open %s", argv[2]);
        size_t cipher_len = fread(ciphertext, 1, sizeof(ciphertext), in_file);
        fclose(in_file);

        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,  // 암호문 입력 버퍼
            TEEC_MEMREF_TEMP_OUTPUT, // 복호화된 평문 출력 버퍼
            TEEC_NONE,
            TEEC_NONE
        );
        op.params[0].tmpref.buffer = ciphertext;
        op.params[0].tmpref.size = cipher_len;
        op.params[1].tmpref.buffer = plaintext;
        op.params[1].tmpref.size = sizeof(plaintext);

        res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSAKEY_DEC, &op, &err_origin);
        if (res != TEEC_SUCCESS)
            errx(1, "TEEC_InvokeCommand (decrypt) failed 0x%x origin 0x%x", res, err_origin);

        // 복호화된 결과 저장
        write_file("plaintext.txt", plaintext);
        printf("Decryption complete. Output: plaintext.txt\n");

    } else {
        printf("Invalid option. Use -e (encryption) or -d (decryption).\n");
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
