#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iomanip>
#include <cstring>

void handleErrors(void) {
    std::cerr << "Error occurred during encryption/decryption!" << std::endl;
    exit(1);
}

void aesEncrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext, unsigned char* ciphertext) {
    AES_KEY enc_key;
    if (AES_set_encrypt_key(key, 128, &enc_key) < 0) {
        handleErrors();
    }
    AES_cbc_encrypt(plaintext, ciphertext, strlen((const char*)plaintext), &enc_key, const_cast<unsigned char*>(iv), AES_ENCRYPT);
}

void aesDecrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* ciphertext, unsigned char* decryptedtext) {
    AES_KEY dec_key;
    if (AES_set_decrypt_key(key, 128, &dec_key) < 0) {
        handleErrors();
    }
    AES_cbc_encrypt(ciphertext, decryptedtext, strlen((const char*)ciphertext), &dec_key, const_cast<unsigned char*>(iv), AES_DECRYPT);
}

void printHex(unsigned char* data, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Key and IV (Initialization Vector) should be 16 bytes (128 bits)
    unsigned char key[16] = "1234567890abcdef"; // 128 bit key
    unsigned char iv[AES_BLOCK_SIZE] = "abcdef1234567890"; // 128 bit IV
    
    // Example plaintext
    unsigned char plaintext[] = "Hello, World! This is a test for AES encryption.";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    std::cout << "Original Plaintext: " << plaintext << std::endl;
    
    // Encrypt the plaintext
    aesEncrypt(key, iv, plaintext, ciphertext);
    std::cout << "Encrypted Ciphertext (in hex): ";
    printHex(ciphertext, sizeof(ciphertext));

    // Decrypt the ciphertext
    aesDecrypt(key, iv, ciphertext, decryptedtext);
    decryptedtext[strlen((const char*)plaintext)] = '\0'; // Null terminate
    std::cout << "Decrypted Text: " << decryptedtext << std::endl;

    return 0;
}
