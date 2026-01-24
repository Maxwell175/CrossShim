/**
 * Test OpenSSL crypto operations in the emulator
 * This tests common operations that the TUTK library uses
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

void test_sha256(void) {
    printf("=== Testing SHA256 ===\n");
    const char* data = "Hello, World!";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    SHA256((unsigned char*)data, strlen(data), hash);
    
    printf("SHA256 of '%s': ", data);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    printf("SHA256 test passed!\n\n");
}

void test_md5(void) {
    printf("=== Testing MD5 ===\n");
    const char* data = "Hello, World!";
    unsigned char hash[MD5_DIGEST_LENGTH];
    
    MD5((unsigned char*)data, strlen(data), hash);
    
    printf("MD5 of '%s': ", data);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    printf("MD5 test passed!\n\n");
}

void test_random(void) {
    printf("=== Testing RAND_bytes ===\n");
    unsigned char buf[16];
    
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        printf("RAND_bytes failed!\n");
        return;
    }
    
    printf("Random bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    printf("RAND_bytes test passed!\n\n");
}

void test_aes_cbc(void) {
    printf("=== Testing AES-128-CBC ===\n");
    
    unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char iv[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const char* plaintext = "Hello, OpenSSL!";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int len, ciphertext_len, decrypted_len;
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    // Encrypt
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, strlen(plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    
    printf("Ciphertext (%d bytes): ", ciphertext_len);
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    
    // Decrypt
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ciphertext_len);
    decrypted_len = len;
    EVP_DecryptFinal_ex(ctx, decrypted + len, &len);
    decrypted_len += len;
    decrypted[decrypted_len] = '\0';
    
    printf("Decrypted: '%s'\n", decrypted);
    
    EVP_CIPHER_CTX_free(ctx);
    printf("AES-128-CBC test passed!\n\n");
}

void test_openssl_init(void) {
    printf("=== Testing OpenSSL Initialization ===\n");
    
    // This is what TUTK likely does during initialization
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    printf("OpenSSL library initialized successfully!\n\n");
}

int main(int argc, char* argv[]) {
    printf("OpenSSL Emulator Test\n");
    printf("=====================\n\n");
    
    // Test basic OpenSSL initialization first
    test_openssl_init();
    
    // Test various crypto operations
    test_md5();
    test_sha256();
    test_random();
    test_aes_cbc();
    
    printf("All OpenSSL tests completed!\n");
    return 0;
}

