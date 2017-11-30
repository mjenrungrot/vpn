/*#include <stdio.h>
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

#include <netinet/in.h>
#include <netdb.h>*/

/* OpenSSL for AES-256 algorithm */
/*#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>*/

/* OpenSSL for SHA-256 algorithm */
//#include <openssl/sha.h>

/* OpenSSL for HMAC algorithm */
//#include <openssl/hmac.h>

/* OpenSSL for Certificates */
//#include <openssl/applink.c> // TODO: Check if this is required.
/*#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
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

#define HOME "./"


/* Certificate Locations */
#define CERTF_CLIENT "CA/client.crt"
#define KEYF_CLIENT "CA/client.key"
#define CERTF_SERVER "CA/server.crt"
#define KEYF_SERVER "CA/server.key"
#define CERTF_CA "CA/CA.crt"

/* OpenSSL Error Checking */
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int debug;
char *progname;

/****** Encryption + Decryption + Hash *********************/

/*HMAC_CTX *hmac;
EVP_CIPHER_CTX *en, *de;
unsigned char key[32];
unsigned char iv[32];

unsigned char* copyBytes(unsigned char *sourceStr, unsigned char *destinationStr, int len);
unsigned char* printHex(unsigned char *string, int len);
void sha256hash(char *string, char outputBuffer[65]);
void generateKeyIV(unsigned char *key, unsigned char *iv);
int aes_hmac_init(unsigned char *key, unsigned char *iv,
	              EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx,
	              HMAC_CTX *hmac);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);*/

/****** HMAC ***********************************************/

/*unsigned char *gen_hmac(HMAC_CTX *hmac, unsigned char *data, int *len);
int check_hmac(unsigned char *hmacA, unsigned char *hmacB, unsigned int nBytes);*/

/****** SSL ***********************************************/

/*void InitializeSSL();
void DestroySSL();
void ShutdownSSL();*/

/****** VPN protocol ***************************************/
/*int tun_alloc(char *dev, int flags);
int cread(int fd, char *buf, int n);
int cwrite(int fd, char *buf, int n);
int read_n(int fd, char *buf, int n);
void do_debug(char *msg, ...);
void my_err(char *msg, ...);*/


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
		
	struct sockaddr_in local;
  struct sockaddr_in remote;
  SSL_CTX* ctx;
  SSL*     ssl;
  SSL_METHOD *meth;
  
  int sock_TCP_fd;
  int optval = 1;
  sock_TCP_fd = socket(AF_INET, SOCK_STREAM, 0);
  
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(1111);
  setsockopt(sock_TCP_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval));
  bind(sock_TCP_fd, (struct sockaddr*)&local, sizeof(local));
  listen(sock_TCP_fd, 5);
  
  size_t remotelen = sizeof(remote);
  int tmp = sock_TCP_fd;
  sock_TCP_fd = accept(sock_TCP_fd, (struct sockaddr*)&remote, &remotelen);
  close(tmp);
  
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSLeay_add_ssl_algorithms();;
  meth = (SSL_METHOD*)SSLv23_server_method();
  ctx = SSL_CTX_new(meth);
  
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_load_verify_locations(ctx, CERTF_CA, NULL);
  SSL_CTX_use_certificate_file(ctx, CERTF_SERVER, SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, KEYF_SERVER, SSL_FILETYPE_PEM);
  
  printf("Connection freom %lx, port %x\n", (long unsigned int)remote.sin_addr.s_addr, remote.sin_port);
  
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock_TCP_fd);
  SSL_accept(ssl);
  printf("SSL connection using %s\n", SSL_get_cipher(ssl));
  return 0;
}


//#include "vpn.h"
