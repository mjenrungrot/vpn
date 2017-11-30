int checkValidHexString(char *string, int len){
	int i;
	for(i=0;i<len;i++){
		// string's length is less than len.
		if(string[i] == 0) return 0;
		
		// skip to a next character if it's a valid hex character.
		if(string[i] >= '0' && string[i] <= '9') continue;
		if(string[i] >= 'a' && string[i] <= 'f') continue;
		if(string[i] >= 'A' && string[i] <= 'F') continue;
		
		// if the string contains non-hex character.
		return 0;
	}
	// return 1 if a string is a valid hex string
	return 1;
}

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

int hexToInt(unsigned char c) {
    if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	return 16;
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

void processVPN(int *pipe_fd, char *pipeBuffer, int tap_fd, int net_fd, char *buffer, int cliserv) {
  uint16_t nwrite;
  uint16_t nread;
  uint16_t plength;
  unsigned long int tap2net = 0;
  unsigned long int net2tap = 0;
  while(1) {
		
		printf("empty pipe buffer\n");
		
		
        int ret;
        fd_set rd_set;

        FD_ZERO(&rd_set);
        FD_SET(tap_fd, &rd_set); 
        FD_SET(net_fd, &rd_set);
        FD_SET(pipe_fd[READ], &rd_set);
        ret = select(FD_SETSIZE, &rd_set, NULL, NULL, NULL);

			printf("Blocking case3\n");
        if (ret < 0 && errno == EINTR){
            continue;
        }

        if (ret < 0) {
            printf("file descriptor = %d\n", (int)ret);
            perror("select()");
            exit(1);
        }
        
        if(FD_ISSET(pipe_fd[READ], &rd_set)){
			// If the buffer in the pipe is not empty, do accoridgly.
			if(read(pipe_fd[READ], pipeBuffer, PIPE_BUF_SIZE) != -1){
				if(!strncmp(pipeBuffer, CHANGE_KEY_COMMAND, 1)){
					unsigned char newkey[32];
					size_t idx; 
					printf("Set new key to ");
					for(idx=0;idx<32;idx++){
						newkey[idx] = pipeBuffer[idx+1]; 
						printf("%02x", newkey[idx]);
					}
					printf("\n");
					EVP_EncryptInit_ex(&en, NULL, NULL, newkey, NULL);	
					EVP_DecryptInit_ex(&de, NULL, NULL, newkey, NULL);
					HMAC_Init_ex(&hmac, newkey, 32, NULL, NULL);
				}else if(!strncmp(pipeBuffer, CHANGE_IV_COMMAND, 1)){
					unsigned char newiv[16];
					size_t idx; 
					printf("Set new IV to ");
					for(idx=0;idx<16;idx++){
						newiv[idx] = pipeBuffer[idx+1]; 
						printf("%02x", newiv[idx]);
					}
					printf("\n");
					EVP_EncryptInit_ex(&en, NULL, NULL, NULL, newiv);	
					EVP_DecryptInit_ex(&de, NULL, NULL, NULL, newiv);
				}else if(!strncmp(pipeBuffer, BREAK_COMMAND, 1)){
					printf("This tunnel will break as notified by the child\n");
					memset(pipeBuffer, 0, sizeof(pipeBuffer));
					if(cliserv == CLIENT) break;
				}
			}
		}

        if(FD_ISSET(tap_fd, &rd_set)){
            // Read input from the TAP interface            
            nread = cread(tap_fd, buffer, BUFSIZE);
            plength = htons(nread);
            
            unsigned char *input, *ciphertext;
            int len = nread;
            input = malloc(len);
            copyBytes(buffer, input, nread);

            // Encrypt the input message
            ciphertext = aes_encrypt(&en, input, &len);
            do_debug("\tinput = %s [%d]\n", printHex(input, nread), nread );
            do_debug("\tciphertext = %s[%d]\n",printHex(ciphertext, len), len);

            // Write the header packet and payload of ciphertext
            plength = htons(len);
            nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
            nwrite = cwrite(net_fd, ciphertext, len);
            
            // Write the HMAC for message verificiation
            len = 84;
            int tmp_len = 84;
            unsigned char* hmac_result = gen_hmac(&hmac, input, &tmp_len);
            nwrite = cwrite(net_fd, hmac_result, len);
            do_debug("\tinput = %s [%d]\n", printHex(input, 84), 84);
            do_debug("\tHMAC = %s [%d]\n", printHex(hmac_result, len), len);
                        
            tap2net++;
            if(cliserv == CLIENT){
                do_debug("TAP2NET %lu: This is sending from TUN [CLIENT] to tunnel Read [%d] Write [%d]\n", tap2net, nread, nwrite);
            }else{
                do_debug("TAP2NET %lu: This is sending from TUN [SERVER] to tunnel Read [%d] Write [%d]\n", tap2net, nread, nwrite);
            }
        }
        if(FD_ISSET(net_fd, &rd_set)){
            /* data from the network: read it, and write it to the tun/tap interface. 
            * We need to read the length first, and then the packet */
            
            // Read the header packet
            nread = read_n(net_fd, (char *)&plength, sizeof(plength));
            int len = ntohs(plength);

            // Read the payload containing encrypted message
            nread = read_n(net_fd, buffer, len);  
            
            // Decrypt the message
            char *decryptedText = (char *)aes_decrypt(&de, buffer, &len);
            int lenDecryptedText = len;
            do_debug("\tciphertext = %s[%d]\n", printHex(buffer, len), len);
            do_debug("\tdecryptedText = %s[%d]\n", printHex(decryptedText, len), len);
            
            // Read the HMAC for message verification
            read_n(net_fd, buffer, 32);
            unsigned char *obtained_hmac = buffer;
            
            // Calculate the HMAC from the received message
            unsigned char *generated_hmac;
            generated_hmac = gen_hmac(&hmac, decryptedText, &len);
            do_debug("\thmac           = %s\n", printHex(buffer, 32));
            do_debug("\tgenerated HMAC = %s [%d]\n", printHex(generated_hmac, len), len);
            
            // Check two HMACs
            if(!check_hmac(obtained_hmac, generated_hmac, (unsigned int)32)){
                perror("HMAC checking failed");
                exit(EXIT_FAILURE);
            }
            
            // Redirect output to the TAP interface
            nwrite = cwrite(tap_fd, decryptedText, lenDecryptedText);
            
            net2tap++;
            if(cliserv == CLIENT){
                do_debug("NET2TAP %lu: Received packets from TUNNEL to [CLIENT] Read [%d] Write [%d]\n", net2tap, nread, nwrite);
            }else{
                do_debug("NET2TAP %lu: Received packets from TUNNEL to [SERVER] Read [%d] Write [%d]\n", net2tap, nread, nwrite);
            }
        }
    }
}


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
