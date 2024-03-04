#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "AES.h"

#define START_IDX 100
#define PRNG_SIZE 20
#define SECRET_LEN_SIZE 10

void shuffle_secret(long long prng, char* secret, int secret_len, char** shuffled_secret) {
    prng = prng % secret_len;
    *shuffled_secret = (char*)malloc(secret_len + 1);
    int index = 0;
    for (int i = 0; i < prng; i++) {
        for (int j = i; j < secret_len; j += prng) {
            (*shuffled_secret)[index++] = secret[j];
        }
    }
    (*shuffled_secret)[secret_len] = '\0'; 
}

void unshuffle_secret(long long prng, char* shuffled_secret, int secret_len, char** unshuffled_secret) {
    prng = prng % secret_len;
    *unshuffled_secret = (char*)malloc(secret_len + 1); 
    int index = 0;
    for (int i = 0; i < prng; i++) {
        for (int j = i; j < secret_len; j += prng) {
            (*unshuffled_secret)[j] = shuffled_secret[index++];
        }
    }
    (*unshuffled_secret)[secret_len] = '\0'; 
}

void hide_message(char* image, int image_len, char* message, int message_len, char* output) {

	memcpy(output, image, image_len);

	// modify LSB
	for (int i = 0; i < message_len * 8; i++) {
		int byte_idx = START_IDX + (i / 8);
		int bit_idx = i % 8;
		int message_bit = (message[i / 8] >> (7 - bit_idx)) & 1;
		output[byte_idx] = (output[byte_idx] & ~(1 << bit_idx)) | (message_bit << bit_idx);
	}
}

void extract_message(char* image, int image_len, char* output, int output_len) {
	int byte_idx, bit_idx;
	char bit;

	memset(output, 0, output_len);

	// extract LSB
	for (int i = 0; i < output_len * 8; i++) {
		byte_idx = START_IDX + i / 8;
		bit_idx = i % 8;
		bit = (image[byte_idx] >> bit_idx) & 1; // extract the bit
		output[i / 8] |= (bit << (7 - (i % 8))); // set the bit 
	}

	output[output_len] = '\0';

	//printf("%s", output);
}

long long get_random() {

    static int seeded = 0;
    if (!seeded) {
        srand(time(NULL));
        seeded = 1;
    }

    return ((long long)rand() << 32) | rand();
}

void phex(uint8_t* str, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

void decrypt_aes(uint8_t* key, uint8_t** ciphertext, size_t* len) {
    // Ensure the key is 32 bytes long.
    uint8_t actual_key[32];
    size_t key_len = strlen((char*)key);

    if (key_len < sizeof(actual_key)) {
        memcpy(actual_key, key, key_len);
        memset(actual_key + key_len, 0, sizeof(actual_key) - key_len); // Zero padding.
    }
    else {
        memcpy(actual_key, key, sizeof(actual_key));
    }

    uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, actual_key, iv);

    AES_CBC_decrypt_buffer(&ctx, *ciphertext, *len);

    // calculate the padding length
    size_t padding_len = (*ciphertext)[*len - 1];

    // check if the padding is valid
    for (size_t i = 0; i < padding_len; i++) {
        if ((*ciphertext)[*len - 1 - i] != padding_len) {
            printf("Invalid padding\n");
            return;
        }
    }

    // remove padding len
    *len -= padding_len;

    // 
    uint8_t* unpadded_ciphertext = (uint8_t*)malloc(*len);
    if (unpadded_ciphertext == NULL) {
        perror("Memory allocation failed");
        return;
    }

    // copy the unpadded plaintext to the new buffer
    memcpy(unpadded_ciphertext, *ciphertext, *len);

    // free the original ciphertext
    free(*ciphertext);

    // update ciphertext to point to the unpadded plaintext
    *ciphertext = unpadded_ciphertext;
}



void encrypt_aes(uint8_t* key, uint8_t** plaintext, size_t* len) {
    
    // ensure that key is 32-bit value
    uint8_t actual_key[32];
    size_t key_len = strlen((char*)key);
    if (key_len < sizeof(actual_key)) {
        memcpy(actual_key, key, key_len);
        memset(actual_key + key_len, 0, sizeof(actual_key) - key_len); // zero padding
    }
    else {
        memcpy(actual_key, key, sizeof(actual_key));
    }

    uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, actual_key, iv);

    // pad secret to be multiple of 16
    size_t padding_len = 16 - (*len % 16);
    uint8_t* padded_plaintext = (uint8_t*)malloc(*len + padding_len);
    memcpy(padded_plaintext, *plaintext, *len);

    for (size_t i = 0; i < padding_len; i++) {
        padded_plaintext[*len + i] = padding_len;
    }

    AES_CBC_encrypt_buffer(&ctx, padded_plaintext, *len + padding_len);

    // update len with padded_len included
    *len += padding_len;

    // free the original plaintext
    free(*plaintext);

    // return the encrypted secret
    *plaintext = padded_plaintext;
}

void generate_message(char* secret,size_t secret_len, char* key, char** message) {
  
   
    size_t encrypted_secret_len = secret_len; 
    size_t message_len = PRNG_SIZE + SECRET_LEN_SIZE + encrypted_secret_len + 1; // +1 for null terminator

    *message = (char*)malloc(message_len);
    if (*message == NULL) {
        perror("Memory allocation failed");
        return;
    }
    memset(*message, 0, message_len);

    long long prng = get_random();
    
    snprintf(*message, PRNG_SIZE + 1, "%0*lld", PRNG_SIZE, prng); // write PRNG to message
    
    // encrypt the secret
    uint8_t* encrypted_secret = (uint8_t*)malloc(encrypted_secret_len);
    if (encrypted_secret == NULL) {
        perror("Memory allocation failed for encrypted secret");
        free(*message);
        return;
    }
    memcpy(encrypted_secret, secret, secret_len);
    
    encrypt_aes((uint8_t*)key, &encrypted_secret, &encrypted_secret_len);
    //phex(encrypted_secret, encrypted_secret_len);
   
    // shuffle the encrypted secret.
    char* shuffled_secret = NULL;
    shuffle_secret(prng, (char*)encrypted_secret, encrypted_secret_len, &shuffled_secret);
    free(encrypted_secret); 

    snprintf(*message + PRNG_SIZE, SECRET_LEN_SIZE + 1, "%0*zu", SECRET_LEN_SIZE, encrypted_secret_len); // write secret length to message
    
    // add the shuffled encrypted secret to message
    memcpy(*message + PRNG_SIZE + SECRET_LEN_SIZE, shuffled_secret, encrypted_secret_len);
    
    phex(*message, message_len);
    free(shuffled_secret); 
}

void parse_message(const char* message, uint8_t* key, long long* prng, size_t* secret_len, char** secret) {
    if (message == NULL || key == NULL || prng == NULL || secret_len == NULL || secret == NULL) {
        printf("Invalid arguments to parse_message function.\n");
        return;
    }


    // extract the fixed-size PRNG value
    char prng_str[PRNG_SIZE + 1]; // +1 for null terminator
    memcpy(prng_str, message, PRNG_SIZE);
    prng_str[PRNG_SIZE] = '\0';
    *prng = atoll(prng_str);

    // extract the fixed-size length of the secret.
    char secret_len_str[SECRET_LEN_SIZE + 1]; // +1 for null terminator.
    memcpy(secret_len_str, message + PRNG_SIZE, SECRET_LEN_SIZE);
    secret_len_str[SECRET_LEN_SIZE] = '\0';
    *secret_len = (size_t)atoll(secret_len_str);

  
    uint8_t* shuffled_encrypted_secret = (uint8_t*)malloc(*secret_len);
    if (shuffled_encrypted_secret == NULL) {
        perror("Memory allocation failed for shuffled encrypted secret");
        return;
    }

    // copy the shuffled encrypted secret from the message
    memcpy(shuffled_encrypted_secret, message + PRNG_SIZE + SECRET_LEN_SIZE, *secret_len);

    // unshuffle the encrypted secret
    char* encrypted_secret = NULL;

    unshuffle_secret(*prng, (char*)shuffled_encrypted_secret, *secret_len, &encrypted_secret);
    free(shuffled_encrypted_secret); 
   
    // decrypt the secret
    decrypt_aes(key, (uint8_t**)&encrypted_secret, secret_len);


    *secret = (char*)malloc(*secret_len + 1); // +1 for null terminator.
    if (*secret == NULL) {
        perror("Memory allocation failed for decrypted secret");
        free(encrypted_secret);
        return;
    }
    memcpy(*secret, encrypted_secret, *secret_len);
    (*secret)[*secret_len] = '\0'; // null-terminate the decrypted secret

    free(encrypted_secret); 
}




