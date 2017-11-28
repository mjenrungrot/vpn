unsigned char* copyBytes(unsigned char *sourceStr, unsigned char *destinationStr, int len){
	int i;
	for(i=0;i < len;i++){
		destinationStr[i] = sourceStr[i];
	}
}

unsigned char* printHex(unsigned char *string, int len){
	unsigned char *output = malloc(2*len+1);
	int i;
	for(i=0;i < len;i++){
		sprintf(output + (i*2), "%02x", string[i]);
	} 
	return output;
}

/**************************************************************************
 * sha256hash: Make a SHA-256 hash of the given string                    *
 **************************************************************************/
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

void generateKeyIV(unsigned char *key, unsigned char *iv){
	if(!RAND_bytes(key, 32)){
		perror("Failed to generate a random key");
		exit(EXIT_FAILURE);
	}
	if(!RAND_bytes(iv, 16)){
		perror("Failed to generate a random IV");
		exit(EXIT_FAILURE);
	}
}

/**************************************************************************
 * aes_hmac_init: Initialize AES + HMAC with given key and IV
 * Expeceted: key - 32 bytes (256-bit) 
 *            iv  - 16 bytes (128-bit)
 **************************************************************************/
int aes_hmac_init(unsigned char *key, unsigned char *iv,
	              EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx,
	              HMAC_CTX *hmac){
	// Encrypt + Decrypt 
	
	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	
	// HMAC
	HMAC_CTX_init(hmac);
	HMAC_Init_ex(hmac, key, 32, EVP_sha256(), NULL);
}

/**************************************************************************
 * aes_encrypt
 * 
 **************************************************************************/
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len){
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);
	*len = c_len + f_len;
	return ciphertext;
}

/**************************************************************************
 * aes_decrypt:
 * 
 **************************************************************************/
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len){
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len);

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);
	*len = p_len + f_len;
	return plaintext;
}

/****** HMAC ***********************************************/

unsigned char *gen_hmac(HMAC_CTX *hmac, unsigned char *data, int *len){
	unsigned char *result = (unsigned char*)malloc(sizeof(char) * (*len));
	
	HMAC_Init_ex(hmac, NULL, (int)NULL, NULL, NULL);
	HMAC_Update(hmac, data, *len);	
	HMAC_Final(hmac, result, len);
	return result;
}

int check_hmac(unsigned char *hmacA, unsigned char *hmacB, unsigned int nBytes){
	int idx;
	for(idx=0;idx<nBytes;idx++){
		if(hmacA[idx] != hmacB[idx]) return 0;
	}
	return 1;
}
	
/***********************************************************
 * Initialize SSL                                          *
 ***********************************************************/
void InitializeSSL() {
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

/***********************************************************
 * Destroy SSL                                             *
 ***********************************************************/
void DestroySSL() {
  ERR_free_strings();
  EVP_cleanup();
}


/***********************************************************
 * Shutdown SSL                                            *
 ***********************************************************/
/*void ShutdownSSL() {
  SSL_shutdown(ssl);
  SSL_free(ssl);
}*/

/****** VPN protocol ***************************************/


/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags){
	int fd, err;
    struct ifreq ifr;

	// Open /dev/net/tun
	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ){
		perror("Error opening /dev/net/tun");
		return fd;
	}

	// Set all values in ifr to be zeros
	memset(&ifr, 0, sizeof(ifr));

	// Set the flags of the device.
	// Example:
	// 		IFF_TUN = TUN interface 
	ifr.ifr_flags = flags;
	
	// Set the name of the device
	if(*dev){
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}
	
	// Register the network device with the kernel
	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ){
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}
	
	// Return the device name at the end.
	strcpy(dev, ifr.ifr_name);
	return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  memset(buf, 0, BUFSIZE);
  int nread;
  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;
  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
	//  printf("left = %d / n = %d\n",left, n);
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}
