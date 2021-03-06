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
#include <signal.h>

/* OpenSSL for AES-256 algorithm */
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

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

/* The index of the "read" end of the pipe */
#define READ 0
/* The index of the "write" end of the pipe */
#define WRITE 1
#define PIPE_BUF_SIZE 100

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

/* command for change iv, change key, and break the tunnel */
#define CHANGE_KEY_COMMAND "1"
#define CHANGE_IV_COMMAND "2"
#define BREAK_COMMAND "3"

/* Certificate Locations */
#define CERTF_CLIENT "./CA/client.crt"
#define KEYF_CLIENT "./CA/client.key"
#define CERTF_SERVER "./CA/server.crt"
#define KEYF_SERVER "./CA/server.key"
#define CERTF_CA "./CA/ca.crt"

/* OpenSSL Error Checking */
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int debug;
char *progname;

struct sockaddr_in local, remote;
socklen_t remotelen;

/****** Encryption + Decryption + Hash *********************/

HMAC_CTX hmac;
EVP_CIPHER_CTX en, de;
unsigned char key[32];
unsigned char iv[32];

int checkValidHexString(char *string, int len);
unsigned char* copyBytes(unsigned char *sourceStr, unsigned char *destinationStr, int len);
int hexToInt(unsigned char c);
unsigned char* printHex(unsigned char *string, int len);
void sha256hash(char *string, char outputBuffer[65]);
void generateKeyIV(unsigned char *key, unsigned char *iv);
int aes_hmac_init(unsigned char *key, unsigned char *iv,
	              EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx,
	              HMAC_CTX *hmac);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);

/****** HMAC ***********************************************/

unsigned char *gen_hmac(HMAC_CTX *hmac, unsigned char *data, int *len);
int check_hmac(unsigned char *hmacA, unsigned char *hmacB, unsigned int nBytes);

/****** SSL ***********************************************/

void InitializeSSL();
void DestroySSL();
void ShutdownSSL();

/****** VPN protocol ***************************************/
int tun_alloc(char *dev, int flags);
int cread(int fd, char *buf, int n);
int cwrite(int fd, char *buf, int n);
int read_n(int fd, char *buf, int n);
void do_debug(char *msg, ...);
void my_err(char *msg, ...);


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
    char buffer[BUFSIZE];			  // General Purpose buffer
	char commandBuffer[BUFSIZE];	  // Buffer for command
	char argumentBuffer[BUFSIZE];	  // Buffer for argument
	char pipeBuffer[PIPE_BUF_SIZE];	  // Buffer for pipe
    char remote_ip[16] = "";
    unsigned short int port = PORT;
    int sock_fd, net_fd, sock_TCP_fd, optval = 1;
    int cliserv = -1;    /* must be specified on cmd line */
    unsigned long int tap2net = 0, net2tap = 0;
    SSL* ssl;						 // SSL Structure
    SSL_CTX* ctx;					 // SSL Structure
    SSL_METHOD* meth;				 // SSL Structure
    X509 *server_cert, *client_cert; // Certificates
    int pipe_fd[2];					 // Unnamed Pipes
	

    progname = argv[0];
  
    /*************************************************************/
    /*************** Read Command Line ***************************/
    /*************************************************************/

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
  
    /*************************************************************/
    /*************** Read Command Line ***************************/
    /*************************************************************/

    /* Initialize tun/tap interface */
    if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
        my_err("Error connecting to tun/tap interface %s!\n", if_name);
        exit(EXIT_FAILURE);
    }
    do_debug("Successfully connected to interface %s\n", if_name);

	signal(SIGCHLD, SIG_IGN);
		
    /* CLIENT: */
    if(cliserv==CLIENT){
		// Create an unnamed pipe
		if(pipe(pipe_fd) < 0){
			perror("error creating unnamed pipe\n");
			exit(EXIT_FAILURE);
		}
		
		// Set the created pipe to be non-blocking
		if (fcntl(pipe_fd[0], F_SETFL, O_NONBLOCK) < 0){
			perror("error making a pipe non-blocking\n");
			exit(EXIT_FAILURE);
		}
		/* Create a socket for SSL's TCP control channel */
		if( (sock_TCP_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
			perror("socket() - SSL's TCP");
			exit(EXIT_FAILURE);
		}
		do_debug("Successfully create a TCP socket\n");
		
		/* Create a socket for VPN's UDP connection */
		if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror("socket() - VPN's UDP");
			exit(EXIT_FAILURE);
		}
		do_debug("Successfully create a UDP socket\n");
		
		
		/* Connect to the server using TCP connection */
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(remote_ip);
		remote.sin_port = htons(port);
		if(connect(sock_TCP_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
			perror("connect() - TCP");
			exit(EXIT_FAILURE);
		}
		do_debug("Successfully connect TCP protocol\n");
		sleep(1);
		
		/* Connect to the server using UDP connection*/
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(remote_ip);
		remote.sin_port = htons(port);
		char *hello = "hello";
		if (sendto(sock_fd, hello, strlen(hello), 0, (struct sockaddr*) &remote, sizeof(remote)) < 0){
			perror("sendto()");
			exit(EXIT_FAILURE);
		}
		if(connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
			perror("connect() - UDP");
			exit(EXIT_FAILURE);
		}
		do_debug("Successfully connect UDP protocol\n");
		
		/* Set the file descriptor */
		net_fd = sock_fd;

		/* Start initializing TLS Connection */
		InitializeSSL();
	
		/* SSL context initialization */
		meth = (SSL_METHOD *)SSLv23_client_method();
		ctx = SSL_CTX_new(meth);
		if(ctx == NULL){
			perror("Create CTX error for Client");
			exit(EXIT_FAILURE);
		}
	
		/* Load certificates for CA */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_load_verify_locations(ctx, CERTF_CA, NULL); 
	
		/* Load certificates for Client */
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
		// Bind the TCP socket with SSL
		SSL_set_fd(ssl, sock_TCP_fd);
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
		
		generateKeyIV(key, iv);
		
		aes_hmac_init(key, iv, &en, &de, &hmac);
		
		SSL_write(ssl, key, 32);
		do_debug("CLIENT: Send key to server\n");
		do_debug("%s\n", printHex(key, 32));
		
		SSL_write(ssl, iv, 16);
		do_debug("CLIENT: Send iv to server\n");
		do_debug("%s\n", printHex(iv, 16));
		
		// Child node for processing TCP protocol
		if(fork() == 0){
			close(pipe_fd[READ]);
			while(1){
				printf("Enter Command  (change_key|change_iv|break): ");
				scanf("%s",commandBuffer);
				
				// Client can change the key by specifying 16 bytes.
				if(!strcmp(commandBuffer, "change_key")){
					printf("Please enter a new key (32 bytes = 64 characters in hex) e.g. ff1100...ab0 : ");
					scanf("%s", argumentBuffer);
					
					if(checkValidHexString(argumentBuffer, 64)){
						do_debug("Client: change_key command is read by the child node\n");
						SSL_write(ssl, CHANGE_KEY_COMMAND, 1);
						SSL_write(ssl, argumentBuffer, 64);
						
						size_t currentBufferLength = 0;
						size_t idx;
						memset(pipeBuffer, 0, sizeof(pipeBuffer));
						
						strncpy(pipeBuffer, CHANGE_KEY_COMMAND, 1);
						currentBufferLength++;
						for(idx=0;idx<64;idx+=2){
							pipeBuffer[currentBufferLength] = (hexToInt(argumentBuffer[idx]) << 4) | hexToInt(argumentBuffer[idx+1]);
							currentBufferLength++;
						}
						
						// write to pipe
						write(pipe_fd[WRITE], pipeBuffer, currentBufferLength);
					}
					
				// Client can change the IV by specifying 16 bytes.
				}else if(!strcmp(commandBuffer, "change_iv")){
					printf("Please enter a new IV (16 bytes = 32 characters in hex) e.g. ff1100...ab0 : ");
					scanf("%s", argumentBuffer);
					
					if(checkValidHexString(argumentBuffer, 32)){
						do_debug("Client: change_iv command is read by the child node\n");
						SSL_write(ssl, CHANGE_IV_COMMAND, 1);  
						SSL_write(ssl, argumentBuffer, 32);
					
						size_t currentBufferLength = 0;
						size_t idx;
						memset(pipeBuffer, 0, sizeof(pipeBuffer));
						
						strncpy(pipeBuffer, CHANGE_IV_COMMAND, 1);
						currentBufferLength++;
						for(idx=0;idx<32;idx+=2){
							pipeBuffer[currentBufferLength] = (hexToInt(argumentBuffer[idx]) << 4) | hexToInt(argumentBuffer[idx+1]);
							currentBufferLength++;
						}
						
						// write to pipe
						write(pipe_fd[WRITE], pipeBuffer, currentBufferLength);
					}
				
				// Client can send a sequence to terminate the VPN connection to the server
				}else if(!strcmp(commandBuffer, "break")){
					do_debug("Client: break command is read by the child node\n");
					SSL_write(ssl, BREAK_COMMAND, 1);  
					
					size_t currentBufferLength = 0;
					memset(pipeBuffer, 0, sizeof(pipeBuffer));	
					strncpy(pipeBuffer, BREAK_COMMAND, 1);
					currentBufferLength++;
					
					// write to pipe
					write(pipe_fd[WRITE], pipeBuffer, currentBufferLength);
					break;
				}
			}
			exit(EXIT_SUCCESS);
			return 0;
		}
		
		// Parent node for processing UDP protocol
		close(pipe_fd[WRITE]);
		goto processVPN;
		
    /* SERVER: */
    } else {
        // Server, wait for connections 
		
		/* Create a socket for SSL's TCP control channel */
		if( (sock_TCP_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
			perror("socker() - SSL's TCP");
			exit(EXIT_FAILURE);
		}
		do_debug("Successfully create a TCP socket\n");
		
		/* Set up the TCP socket */
		optval = 1;
		if(setsockopt(sock_TCP_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
			perror("setsockopt() - TCP");
			exit(EXIT_FAILURE);
		}
		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = htonl(INADDR_ANY);
		local.sin_port = htons(port);
		if(bind(sock_TCP_fd, (struct sockaddr*)&local, sizeof(local)) < 0){
			perror("Server: bind() - TCP");
			exit(EXIT_FAILURE);
		}
		if(listen(sock_TCP_fd, 5) < 0){
			perror("Server: listen() - TCP");
			exit(EXIT_FAILURE);
		}
		
		int new_sock_TCP;
		while(1){
			/* Wait for a TCP connection */
			remotelen = sizeof(remote);
			memset(&remote, 0, remotelen);
			if((new_sock_TCP = accept(sock_TCP_fd, (struct sockaddr*)&remote, &remotelen)) < 0){
				perror("Server: accept() - TCP");
				exit(EXIT_FAILURE);
			}
			
			// Child node takes care of each connection
			if(fork() == 0){
				sock_TCP_fd = new_sock_TCP;
				
				/* Create a pipe */
				if(pipe(pipe_fd) < 0){
					perror("error creating unnamed pipe\n");
					exit(EXIT_FAILURE);
				}
				
				/* Make a pipe non-blocking */
				if (fcntl(pipe_fd[0], F_SETFL, O_NONBLOCK) < 0){
					perror("error making a pipe non-blocking\n");
					exit(EXIT_FAILURE);
				}
				
				
				/* Create a socket for VPN's UDP connection */
				if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
					perror("socket() - VPN's UDP");
					exit(EXIT_FAILURE);
				}
				
				/* Setup the socket for UDP connection */
				optval = 1;
				if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
					perror("setsockopt() - TCP");
					exit(EXIT_FAILURE);
				}
				memset(&local, 0, sizeof(local));
				local.sin_family = AF_INET;
				local.sin_addr.s_addr = htonl(INADDR_ANY);
				local.sin_port = htons(port);
				if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
					perror("bind() - UDP");
					exit(EXIT_FAILURE);
				}
				
				/* Receive the connetion request */
				remotelen = sizeof(remote);
				memset(&remote, 0, remotelen);
				int len;
				if ((len = recvfrom(sock_fd, buffer, BUFSIZE, 0, (struct sockaddr*)&remote, &remotelen)) < 0){
					perror("recvfrom() - UDP");
					exit(EXIT_FAILURE);
				};
				
				/* Receive the actual connection */
				if(connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
					perror("connect() - UDP");
					exit(EXIT_FAILURE);
				}
				do_debug("Server: Finish UDP connection\n");
				net_fd = sock_fd;
				
				
				
				/* SSL context initialization */
				InitializeSSL();
				meth = (SSL_METHOD *)SSLv23_server_method();
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
				SSL_set_fd(ssl, sock_TCP_fd);
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

				SSL_read(ssl, key, 32);
				do_debug("SERVER: Read key from client\n");
				do_debug("%s\n", printHex(key, 32));
				
				SSL_read(ssl, iv, 16);
				do_debug("SERVER: Read IV from client\n");
				do_debug("%s\n", printHex(iv, 16));
				
				// Initialize AES + HMAC with the client's session key and IV
				aes_hmac_init(key, iv, &en, &de, &hmac);
				
				// Child node takes care of TCP's control channel
				if(fork() == 0){
					close(pipe_fd[READ]);
					
					// Keep reading command sending over SSL 
					while(1){
						SSL_read(ssl, commandBuffer, 1);
						if(!strncmp(commandBuffer, CHANGE_KEY_COMMAND, 1)){
							memset(commandBuffer, 0, sizeof(commandBuffer));
							memset(argumentBuffer, 0, sizeof(argumentBuffer));
							SSL_read(ssl, argumentBuffer, 64);
							
							size_t currentBufferLength = 0;
							size_t idx;
							memset(pipeBuffer, 0, sizeof(pipeBuffer));
							
							strncpy(pipeBuffer, CHANGE_KEY_COMMAND, 1);
							currentBufferLength++;
							for(idx=0;idx<64;idx+=2){
								pipeBuffer[currentBufferLength] = hexToInt(argumentBuffer[idx]) << 4 | hexToInt(argumentBuffer[idx+1]);
								currentBufferLength++;
							}
							
							// write to pipe
							write(pipe_fd[WRITE], pipeBuffer, currentBufferLength);
							
							do_debug("The server will set a new key to %s\n", argumentBuffer);
						}else if(!strncmp(commandBuffer, CHANGE_IV_COMMAND, 1)){
							memset(commandBuffer, 0, sizeof(commandBuffer));
							memset(argumentBuffer, 0, sizeof(argumentBuffer));
							SSL_read(ssl, argumentBuffer, 32);
							
							size_t currentBufferLength = 0;
							size_t idx;
							memset(pipeBuffer, 0, sizeof(pipeBuffer));
							
							strncpy(pipeBuffer, CHANGE_IV_COMMAND, 1);
							currentBufferLength++;
							for(idx=0;idx<32;idx+=2){
								pipeBuffer[currentBufferLength] = hexToInt(argumentBuffer[idx]) << 4 | hexToInt(argumentBuffer[idx+1]);
								currentBufferLength++;
							}
							
							// write to pipe
							write(pipe_fd[WRITE], pipeBuffer, currentBufferLength);
							
							do_debug("The server will set a new iv to %s\n", argumentBuffer);
						}else if(!strncmp(commandBuffer, BREAK_COMMAND, 1)){
							memset(commandBuffer, 0, sizeof(commandBuffer));
							do_debug("The server will break the tunnel\n");
							
							size_t currentBufferLength = 0;
							memset(pipeBuffer, 0, sizeof(pipeBuffer));	
							strncpy(pipeBuffer, BREAK_COMMAND, 1);
							currentBufferLength++;
							
							// write to pipe
							write(pipe_fd[WRITE], pipeBuffer, currentBufferLength);
							break;
						}
					}
					exit(EXIT_SUCCESS);
					return 0;
				}
				
				// Parent node takes care of UDP connection.
				close(pipe_fd[WRITE]);
				goto processVPN;
			
			
			// Parent node does not need to perform anything but looks for another incoming connection.
			}else{
				close(new_sock_TCP);
			}
		}
    }
    
    processVPN:
    while(1) {
        int ret;
        fd_set rd_set;

        FD_ZERO(&rd_set);
        FD_SET(tap_fd, &rd_set); 
        FD_SET(net_fd, &rd_set);
        FD_SET(pipe_fd[READ], &rd_set);
        ret = select(FD_SETSIZE, &rd_set, NULL, NULL, NULL);

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
					memset(pipeBuffer, 0, sizeof(pipeBuffer));
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
					memset(pipeBuffer, 0, sizeof(pipeBuffer));
				}else if(!strncmp(pipeBuffer, BREAK_COMMAND, 1)){
					printf("One of the connections is terminated.\n");
					memset(pipeBuffer, 0, sizeof(pipeBuffer));
					break;
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
			int inputLength = len;
            ciphertext = aes_encrypt(&en, input, &len);
            do_debug("\tinput = %s [%d]\n", printHex(input, nread), nread);
            do_debug("\tciphertext = %s[%d]\n",printHex(ciphertext, len), len);

            // Write the header packet and payload of ciphertext
            plength = htons(len);
            nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
            nwrite = cwrite(net_fd, ciphertext, len);
            
            // Write the HMAC for message verificiation
            int tmp_len = len;
            len = tmp_len;
            unsigned char* hmac_result = gen_hmac(&hmac, input, &inputLength);
            nwrite = cwrite(net_fd, hmac_result, 32);
            
            do_debug("\tHMAC = %s [%d]\n", printHex(hmac_result, 32), 32);
                        
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
            do_debug("\tciphertext = %s[%d]\n", printHex(buffer, len), len);
            
            // Decrypt the message
            char *decryptedText = (char *)aes_decrypt(&de, buffer, &len);
            int lenDecryptedText = len;
            
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
    
    // Shutdown connections and close related file descriptors.
    if(shutdown(sock_TCP_fd, SHUT_RDWR) < 0){
		printf("Shutdown failed\n");
	}
    close(sock_TCP_fd);
    close(net_fd);
    close(pipe_fd[READ]);
    return 0;
}

#include "vpn.h"
