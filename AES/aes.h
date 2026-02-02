#ifndef AES_H
#define AES_H

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   16

#define ENCRYPTION_MODE 1
#define DECRYPTION_MODE 0

typedef unsigned char uint8;

/* Key schedule */
void aes_key_expansion(uint8 *key, uint8 *round_keys);

/* Block operations */
void aes_encrypt_block(uint8 *input, uint8 *output, uint8 *round_keys);
void aes_decrypt_block(uint8 *input, uint8 *output, uint8 *round_keys);

#endif

