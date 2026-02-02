#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>

#include "des.h"   // <-- IMPORTANT

void timeout_handler(int sig) {
    printf("\n[-] 10 second timeout reached. Exiting.\n");
    exit(0);
}

int looks_printable(unsigned char *buf, int len) {
    for (int i = 0; i < len; i++) {
        if (!isprint(buf[i]) && buf[i] != '\n')
            return 0;
    }
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s file.enc\n", argv[0]);
        return 1;
    }

    /* ⏱ hard 10-second cutoff */
    signal(SIGALRM, timeout_handler);
    alarm(10);

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    unsigned char cipher[8];
    if (fread(cipher, 1, 8, f) != 8) {
        fprintf(stderr, "Could not read 8 bytes from ciphertext\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    unsigned char plain[8];
    unsigned char key[8];
    key_set key_sets[17];

    /* 🔑 REDUCED KEYSPACE (LAB ASSUMPTION) */
    uint32_t MAX_KEYS = 1 << 24;   // ~16 million

    for (uint32_t k = 0; k < MAX_KEYS; k++) {
        memset(key, 0, 8);
        memcpy(key, &k, sizeof(k));

        generate_sub_keys(key, key_sets);
        process_message(cipher, plain, key_sets, DECRYPTION_MODE);

        if (looks_printable(plain, 8)) {
            printf("[+] Possible key: 0x%08x\n", k);
            printf("[+] Plaintext block: %.8s\n", plain);
            return 0;
        }
    }

    printf("[-] No key found in searched keyspace.\n");
    return 0;
}
