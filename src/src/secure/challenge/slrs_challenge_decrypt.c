#include "./aes_128_cbc.h"
#include <string.h>

int main (void)
{
	unsigned char key_128[16] = { 0x40, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
						   0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x45
						 };

	// TODO - Must be unpredictable (random), but need not be secret.
	// Can be prepended to the plaintext before encryption, rather than computed on each side.
	// The *unused* portion of aesciphertext could be used here, because it's not sent over the air.
	unsigned char iv[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
						  0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
						};

	unsigned char plaintext[8] = {0, 0, 0, 0, 0, 0, 2, 1};
	unsigned char msgdecrypted[8];

	union bytes8
	{
		uint64_t i;
		unsigned char ch[8];
	};
	union bytes8 counter;
	counter.i = 0x0400;
	union bytes8 ciphermask;

	unsigned char aesciphertext[32];
	unsigned char msgciphertext[32];

	/* Buffer for the decrypted text */
	unsigned char aesdecryptedtext[32];

	int aesciphertext_len;

	printf("Counter before encryption is:\n");
	// printf("%s\n", aesdecryptedtext);
	BIO_dump_fp (stdout, (const char *)counter.ch, 8);

	aesciphertext_len = encrypt_aes_128_cbc (counter.ch, 16, key_128, iv, aesciphertext);
	counter.i += 0x0100;

	for(int i=0; i<8; i++)
		msgciphertext[i] = (unsigned char)(plaintext[i] ^ aesciphertext[i]);


	/* Decrypt the ciphertext */
	decrypt_aes_128_cbc(aesciphertext, aesciphertext_len, key_128, iv, aesdecryptedtext);

	/* Add a NULL terminator. We are expecting printable text */
	// aesdecryptedtext[aesdecryptedtext_len] = '\0';

	/* Show the decrypted text */
	printf("Decrypted aes text is:\n");
	// printf("%s\n", aesdecryptedtext);
	BIO_dump_fp (stdout, (const char *)aesdecryptedtext, 8);

	for(int i=0; i<8; i++)
		msgdecrypted[i] = (unsigned char)(msgciphertext[i] ^ aesciphertext[i]);

	printf("Decrypted msg text is:\n");
	BIO_dump_fp (stdout, (const char *)msgdecrypted, 8);

 return 0;
}

