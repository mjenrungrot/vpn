#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

/* OpenSSL for AES-256 algorithm */
#include <openssl/evp.h>
#include <openssl/aes.h>

/* OpenSSL for SHA-256 algorithm */
#include <openssl/sha.h>

/* OpenSSL for HMAC algorithm */
#include <openssl/hmac.h>

/* OpenSSL for Certificates */
//#include <openssl/applink.c> // TODO: Check if this is required.
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

/* Certificate Locations */
#define CERTF_CLIENT "./CA/client.crt"
#define KEYF_CLIENT "./CA/client.key"
#define CERTF_SERVER "./CA/server.crt"
#define KEYF_SERVER "./CA/server.key"
#define CERTF_CA "./CA/crt"

/* OpenSSL Error Checking */
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int debug;
char *progname;

struct sockaddr_in local, remote;
socklen_t remotelen;

/****** Encryption + Decryption + Hash *********************/

HMAC_CTX *hmac;
EVP_CIPHER_CTX *en, *de;
unsigned int salt[] = {12345, 54321};
unsigned char *key_data = "key";
int key_data_len = 3;

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

/**************************************************************************
 * aes_hmac_init: Generate random key + iv
 * 
 **************************************************************************/
int aes_hmac_init(unsigned char *key_data, int key_data_len, unsigned char *salt,
	              EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx,
	              HMAC_CTX *hmac){
	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if( i != 32 ){
		printf("Key size = %d\n", i);
		return -1;
	}

	// Encrypt + Decrypt 
	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	
	// HMAC
	HMAC_CTX_init(hmac);
	HMAC_Init_ex(hmac, key_data, (int)strlen(key_data), EVP_sha256(), NULL);
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

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]){
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  SSL* ssl;				// SSL Structure
  SSL_CTX* ctx;
  SSL_METHOD* meth;
  X509 *server_cert, *client_cert; // Certificates

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }
  
  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  // Use SOCK_DGRAM for UDP connections
  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }
  if(cliserv==CLIENT){
    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    /* connection request */
    char *hello = "hello";
    if (sendto(sock_fd, hello, strlen(hello), 0, (struct sockaddr*) &remote, sizeof(remote)) < 0){
      perror("sendto()");
      exit(1);
    }
    
    /* Provide a destination for UDP connections */
	if(connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
		perror("connect()");
		exit(1);
	}
	
    net_fd = sock_fd;

	/* Start initializing TLS Connection */
	InitializeSSL();
	
	// SSL context initialization
	meth = (SSL_METHOD *)SSLv23_client_method();
	ctx = SSL_CTX_new(meth);
	
	if(ctx == NULL){
		perror("Create CTX error for Client");
		exit(EXIT_FAILURE);
	}
	
	/* Load certificates of CA */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CERTF_CA, NULL); 
	
	/* Load certificates of Client */
	if(SSL_CTX_use_certificate_file(ctx, CERTF_CLIENT, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, KEYF_CLIENT, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if(!SSL_CTX_check_private_key(ctx)){
		perror("Private key doesn't match the certificate public key");
		exit(EXIT_FAILURE);
	}
	
	// Create a new SSL structure for a connection
	if((ssl = SSL_new(ctx)) == NULL){
		perror("Error with making SSL connection from Client");
		exit(EXIT_FAILURE);
	}
	SSL_set_fd(ssl, sock_fd);
	if(SSL_connect(ssl) == -1){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	 
	/* Get the cipher opt */
    do_debug("CLIENT: SSL Connection using %s\n", SSL_get_cipher(ssl));
    
    /* Get server's certificate */
    if((server_cert = SSL_get_peer_certificate(ssl)) == NULL){
		perror("Can't get server's certificate");
		exit(EXIT_FAILURE);
	}
	
	char *certificateBuffer;
	certificateBuffer = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	if(certificateBuffer == NULL){
		perror("Can't get the subject from the server's certificate");
		exit(EXIT_FAILURE);
	}
	OPENSSL_free(certificateBuffer);
	
	certificateBuffer = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	if(certificateBuffer == NULL){
		perror("Can't get the issuer from the server's certificate");
		exit(EXIT_FAILURE);
	}
	OPENSSL_free(certificateBuffer);
	
	/* Deallocating the certificate */
	X509_free(server_cert);
    
    do_debug("CLIENT: SSL Connection to server %s is sucessful\n", inet_ntoa(remote.sin_addr));
  } else {
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    
    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    int len;
    if ((len = recvfrom(sock_fd, buffer, BUFSIZE, 0, (struct sockaddr*)&remote, &remotelen)) < 0){
      perror("recvfrom()");
      exit(1);
    }
    
    if(connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
		perror("connect()");
		exit(1);
	}
    net_fd = sock_fd;

	/* SSL context initialization */
	InitializeSSL();
	meth = (SSL_METHOD *)SSLv23_client_method();
	ctx = SSL_CTX_new(meth);
	
	if(ctx == NULL){
		perror("Create CTX error for Server");
		exit(EXIT_FAILURE);
	}
	
	/* Load certificates for CA */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CERTF_CA, NULL);
	
	/* Load certificates for Server */
	if(SSL_CTX_use_certificate_file(ctx, CERTF_SERVER, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, KEYF_SERVER, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if(!SSL_CTX_check_private_key(ctx)){
		perror("Private key doesn't match the certificate public key");
		exit(EXIT_FAILURE);
	}
	
	// Create a new SSL structure for a connection
	if((ssl = SSL_new(ctx)) == NULL){
		perror("Error with making SSL connection from Server");
		exit(EXIT_FAILURE);
	}
	SSL_set_fd(ssl, sock_fd);
	if(SSL_accept(ssl) == -1){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
	/* Get the cipher */
	do_debug("SERVER: SSL Connection using %s\n", SSL_get_cipher(ssl));
	
	/* Get client's certificate */
	if((client_cert = SSL_get_peer_certificate(ssl)) == NULL){
		perror("Can't get client's certificate");
		exit(EXIT_FAILURE);
	}
	
	char *certificateBuffer;
	certificateBuffer = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
	if(certificateBuffer == NULL){
		perror("Can't get the subject from the client's certificate");
		exit(EXIT_FAILURE);
	}
	OPENSSL_free(certificateBuffer);
	
	certificateBuffer = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
	if(certificateBuffer == NULL){
		perror("Can't get the issuer from the client's certificate");
		exit(EXIT_FAILURE);
	}
	OPENSSL_free(certificateBuffer);
	
	/* Deallocating the certificate */
	X509_free(client_cert);
    
    do_debug("SERVER: SSL Connection from client %s is sucessful\n", inet_ntoa(remote.sin_addr));
  }
  
  // Initialize AES
  aes_hmac_init(key_data, key_data_len, (unsigned char*)&salt, en, de, hmac);

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); 
    FD_SET(net_fd, &rd_set);
    ret = select(FD_SETSIZE, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
	  printf("file descriptor = %d\n", (int)ret);
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
		nread = cread(tap_fd, buffer, BUFSIZE);
		plength = htons(nread);
		
		unsigned char *input;
		int len = nread;
		input = malloc(len);
		copyBytes(buffer, input, nread);
		
		unsigned char *ciphertext;
	    ciphertext = aes_encrypt(en, input, &len);
		do_debug("\tinput = %s [%d]\n", printHex(input, nread), nread );
		do_debug("\tciphertext = %s[%d]\n",printHex(ciphertext, len), len);
		// fix the length of the header
		plength = htons(len);
		//printf("len = %d\n", len);
		//printf("header size = %s\n", printHex((char *)&plength, 2));
		//printf("header size = %s\n", printHex((char *)&plength, 2));
		nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
		nwrite = cwrite(net_fd, ciphertext, len);
		
		len = 84;
		int tmp_len = 84;
		unsigned char* hmac_result = gen_hmac(hmac, input, &tmp_len);
		do_debug("\tinput = %s [%d]\n", printHex(input, 84), 84);
		do_debug("\tHMAC = %s [%d]\n", printHex(hmac_result, len), len);
		nwrite = cwrite(net_fd, hmac_result, len);
		
		tmp_len = 84;
		do_debug("\tinput = %s [%d]\n", printHex(input, 84), 84);
		do_debug("\tHMAC = %s [%d]\n", printHex(hmac_result, tmp_len), tmp_len);
		
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
        
		nread = read_n(net_fd, (char *)&plength, sizeof(plength));
		
		int len = ntohs(plength);
        nread = read_n(net_fd, buffer, len);  
        
		do_debug("\tciphertext = %s[%d]\n", printHex(buffer, len), len);
		char *decryptedText = (char *)aes_decrypt(de, buffer, &len);
		do_debug("\tdecryptedText = %s[%d]\n", printHex(decryptedText, len), len);
		
		read_n(net_fd, buffer, 32);
		unsigned char *obtained_hmac = buffer;
		do_debug("\thmac           = %s\n", printHex(buffer, 32));
		
		unsigned char *generated_hmac;
		generated_hmac = gen_hmac(hmac, decryptedText, &len);
		do_debug("\tgenerated HMAC = %s [%d]\n", printHex(generated_hmac, len), len);
		
		nwrite = cwrite(tap_fd, decryptedText, len);
		
		if(check_hmac(obtained_hmac, generated_hmac, (unsigned int)32)){
			perror("HMAC checking failed");
			exit(EXIT_FAILURE);
		}
		
		net2tap++;
		if(cliserv == CLIENT){
			do_debug("NET2TAP %lu: Received packets from TUNNEL to [CLIENT] Read [%d] Write [%d]\n", net2tap, nread, nwrite);
		}else{
			do_debug("NET2TAP %lu: Received packets from TUNNEL to [SERVER] Read [%d] Write [%d]\n", net2tap, nread, nwrite);
		}
    }
  }
  
  return 0;
}