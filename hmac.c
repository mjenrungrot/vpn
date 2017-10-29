#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>

int main(){
	char key[] = "012345678";
	char data[] = "hello world";

	unsigned char* digest;
	digest = HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);

	char mdString[20];
	for(int i=0;i<20;i++){
		sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	}
	printf("HMAC digest: %s\n", mdString);
	return 0;
}
