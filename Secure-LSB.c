#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "helper.h"


void handle_hide(char* key, char* fimage, char* fsecret, char* foutput) {
    
    FILE* fp_image = fopen(fimage, "rb");
    FILE* fp_secret = fopen(fsecret, "rb");
    FILE* fp_output = fopen(foutput, "wb");

    if (fp_image == NULL || fp_secret == NULL || fp_output == NULL) {
        perror("Failed to open file");
        exit(2);
    }

    int image_len = 0, secret_len = 0;

    fseek(fp_image, 0, SEEK_END);
    image_len = ftell(fp_image);
    rewind(fp_image);

    fseek(fp_secret, 0, SEEK_END);
    secret_len = ftell(fp_secret);
    rewind(fp_secret);

    char* image = malloc(image_len);     // store input image
    char* secret = malloc(secret_len);   // store secret
    char* output = malloc(image_len);    // store output 

    if (image == NULL || secret == NULL || output == NULL) {
        perror("Failed to allocate memory");
        exit(4);
    }

    fread(image, 1, image_len, fp_image);
    fread(secret, 1, secret_len, fp_secret);

    if (image_len <= secret_len) {
        printf("Input message must be shorter than the input image.");
        exit(3);
    }

    char* message = malloc(sizeof(secret) + sizeof(secret));
    //printf("%s %s", secret, key);
    
    generate_message(secret, secret_len, key, &message);
 
    
    size_t message_len = PRNG_SIZE + SECRET_LEN_SIZE + secret_len+(16-secret_len%16);
    //phex(message, message_len);
   
    hide_message(image, image_len, message, message_len, output);
 
    size_t written = fwrite(output, 1, image_len, fp_output);
    if (written != image_len) {
        perror("Failed to write to output file");
        exit(5);
    }

    free(message);
}

void handle_extract(char* key, char* fimage, char* foutput) {

    FILE* fp_image = fopen(fimage, "rb");

    if (fp_image == NULL) {
        perror("Failed to open file");
        exit(2);
    }

    int image_len = 0;

    fseek(fp_image, 0, SEEK_END);
    image_len = ftell(fp_image);
    rewind(fp_image);

    char* image = malloc(image_len);

    if (image == NULL) {
        perror("Failed to allocate memory");
        exit(4);
    }

    fread(image, 1, image_len, fp_image);

 
    int output_len = PRNG_SIZE + SECRET_LEN_SIZE + image_len; // adjust image_len value as needed
    char* output = malloc(output_len + 1); // +1 for null terminator.
    if (output == NULL) {
        perror("Failed to allocate memory for output");
        exit(7);
    }

    extract_message(image, image_len, output, output_len);
    output[output_len] = '\0'; 

    long long prng;
    size_t secret_len;
    char* decrypted_secret = NULL;

    parse_message(output, key, &prng, &secret_len, &decrypted_secret);

    // Save the output to a file
    FILE* fp_output = fopen(foutput, "w");
    if (fp_output == NULL) {
        perror("Failed to open output file");
        exit(8);
    }
    fwrite(decrypted_secret, sizeof(char), secret_len, fp_output);
    fclose(fp_output);
}


int main(int argc, char* argv[]) {
    if (!((argc == 6 && strcmp(argv[1], "hide") == 0) || (argc == 5 && strcmp(argv[1], "extract") == 0))) {
        printf("Usage:\n\t%s hide <key> <input_image> <input_message_file> <output>\n\t%s extract <key> <input_image> <output>\n", argv[0], argv[0]);
        exit(1);
    }

    char* key = argv[2];
    char* fimage = argv[3];
    char* fsecret = (argc == 6) ? argv[4] : NULL;
    char* foutput = (argc == 6) ? argv[5] : argv[4];

    if (strcmp(argv[1], "hide") == 0) {
        handle_hide(key, fimage, fsecret, foutput);
    }
    else if (strcmp(argv[1], "extract") == 0) {
        handle_extract(key, fimage, foutput);
    }
    else {
        printf("Invalid option!");
        exit(6);
    }

    return 0;
}

