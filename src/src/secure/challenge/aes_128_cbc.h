#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

// Note - Disable padding if encrypting exactly the block size.
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt_aes_128_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{   
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;
    
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
     
     /* Ensure you use corect key & IV size.
     * aes128 is 128-bit key. IV size for *most* modes is the same as the block size.
     * For AES that is 128 bits. */ 
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
     
     /* EVP_EncryptUpdate can be called multiple times if necessary */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    
    /* Finalise. This may write more ciphertext bytes.  */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_aes_128_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

     /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary. */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise. Further plaintext bytes may be written by this. */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

#define aes_block_size	32
#define aes_iv_size		16

