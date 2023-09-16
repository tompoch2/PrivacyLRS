#include "./aes_128_cbc.h"
#include <string.h>

union bytes8
{
    uint64_t i;
    unsigned char ch[8];
};

void  get_random(int bytes, unsigned char *output) {
	FILE *fd;
	fd = fopen("/dev/random","rb");
	fread(output,bytes,1,fd);
	fclose(fd);
}


void do_message(unsigned char *counter, unsigned char *key_128, unsigned char *iv, unsigned char* plaintext) {

    unsigned char aesciphertext[32];
    unsigned char msgciphertext[32];

    encrypt_aes_128_cbc (counter, 16, key_128, iv, aesciphertext);
	memcpy(iv, aesciphertext + aes_block_size / 2, aes_iv_size);

    for(int i=0; i<8; i++)
        msgciphertext[i] = (unsigned char)(plaintext[i] ^ aesciphertext[i]);

    printf("MSG ciphertext is:\n");
    for(int i=0; i<7; i++)
        printf("0x%02X, ", (unsigned char) msgciphertext[i] );
    printf("0x%02X\n", (unsigned char) msgciphertext[7] );
}


int main (void)
{

	// Key is not provided to the attacker, of course.
	unsigned char key_128[16] = {
							0x40, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
							0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x45
						 };
	// Must be unpredictable (random), but need not be secret.
	// Can be prepended to the plaintext before encryption, rather than computed on each side.
	// The *unused* portion of aesciphertext could be used here.
	unsigned char iv[aes_iv_size];


	get_random(aes_iv_size, iv);

	printf("IV is: ");
    for(int i=0; i<aes_iv_size - 1; i++)
        printf("0x%02X, ", (unsigned char) iv[i] );
    printf("0x%02X\n", (unsigned char) iv[aes_iv_size] );

	union bytes8 counter;
	counter.i = 0x0100;
	
    unsigned char plaintext[9];
    printf("Enter 8 bytes of plaintext: ");
	while( fscanf(stdin,"%8s", plaintext) != EOF ) {
		do_message(counter.ch, key_128, iv, plaintext);
		counter.i += 0x0100;
	}

	return 0;
}

