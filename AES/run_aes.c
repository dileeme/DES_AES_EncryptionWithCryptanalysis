#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "aes.h"

#define ACTION_GENERATE_KEY "-g"
#define ACTION_ENCRYPT "-e"
#define ACTION_DECRYPT "-d"

int main(int argc, char *argv[]) {
    if (argc != 3 && argc != 5) {
        printf("Usage:\n");
        printf("  run_aes -g keyfile\n");
        printf("  run_aes -e keyfile input output\n");
        return 1;
    }

    /* ---------- Generate Key ---------- */
    if (!strcmp(argv[1], ACTION_GENERATE_KEY)) {
        FILE *kf = fopen(argv[2], "wb");
        if (!kf) return 1;

        srand(time(NULL));
        unsigned char key[AES_KEY_SIZE];
        for (int i = 0; i < AES_KEY_SIZE; i++)
            key[i] = rand() % 256;

        fwrite(key, 1, AES_KEY_SIZE, kf);
        fclose(kf);
        return 0;
    }

    /* ---------- Encrypt ---------- */
    FILE *kf = fopen(argv[2], "rb");
    FILE *in = fopen(argv[3], "rb");
    FILE *out = fopen(argv[4], "wb");

    if (!kf || !in || !out) {
        printf("File error\n");
        return 1;
    }

    unsigned char key[AES_KEY_SIZE];
    if (fread(key, 1, AES_KEY_SIZE, kf) != AES_KEY_SIZE) {
        printf("Key read error\n");
        return 1;
    }
    fclose(kf);

    unsigned char rk[176];
    aes_key_expansion(key, rk);

    unsigned char block[16], outblock[16];
    size_t n;

    while ((n = fread(block, 1, 16, in)) > 0) {
        if (n < 16) {
            unsigned char pad = 16 - n;
            memset(block + n, pad, pad);
        }
        aes_encrypt_block(block, outblock, rk);
        fwrite(outblock, 1, 16, out);
    }

    fclose(in);
    fclose(out);
    return 0;
}
