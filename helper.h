#pragma once

#include <stdint.h>

#define START_IDX 54
#define PRNG_SIZE 20
#define SECRET_LEN_SIZE 10

void hide_message(char* image, int image_len, char* message, int message_len, char* output);
void extract_message(char* image, int image_len, char* output, int output_len);
void generate_message(char* secret, size_t secret_len,char* key, char** message);
void parse_message(const char* message, uint8_t* key, long long* prng, size_t* secret_len, char** secret);