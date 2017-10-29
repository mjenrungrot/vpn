#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

void sha256hash(char *string, char outputBuffer[65]){
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, string, strlen(string));
	SHA256_Final(hash, &sha256);
	int i = 0;
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++){
		sprintf(outputBuffer + (i*2), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
}

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt,
	     EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx){
	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if( i != 32 ){
		printf("Key size = %d\n", i);
		return -1;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len){
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len){
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len);

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}

int main(int argc, char* argv[]){
	EVP_CIPHER_CTX en, de;
	unsigned int salt[] = {12345, 54321};
	unsigned char *key_data;
	int key_data_len;
	char *input = "adafadsfasfkadslkfpdsakpfpasdkfakdslfkfdpkbcd";

	key_data = (unsigned char*)argv[1];
	key_data_len = strlen(argv[1]);

	aes_init(key_data, key_data_len, (unsigned char*)&salt, &en, &de);

	char *plaintext;
	unsigned char *ciphertext;
	int olen, len;
	olen = len =strlen(input) + 1;
	
	ciphertext = aes_encrypt(&en, (unsigned char*)input, &len);
	plaintext = (char *)aes_decrypt(&de, ciphertext, &len);

	printf("input = %s\n",input);
	printf("ciphertext = %s\n", ciphertext);
	printf("plaintext = %s\n", plaintext);
	printf("strncmp = %d\n",strncmp(plaintext, input, olen));
	return 0;
}

