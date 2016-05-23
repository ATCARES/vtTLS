/* serv.cpp  -  Minimal ssleay server for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */


/* mangled to work with OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

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
#include <sys/time.h>

#include <supertls/rsa.h>
#include <supertls/crypto.h>
#include <supertls/x509.h>
#include <supertls/pem.h>
#include <supertls/ssl.h>
#include <supertls/err.h>

#include <string>

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */

/*ECDHE-ECDSA*/
#define ECDH_CERTF  "server-ecdhe-cert.crt"
#define ECDH_KEYF   "server-ecdhe-key.pem"

#define RSA_CERTF   "server_rsa.crt"
#define RSA_KEYF    "server_rsa.key"

#define ECDH2_CERTF    "server-dh-cert.crt"
#define ECDH2_KEYF     "server-dh-key.pem"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main (int argc, char* argv[])
{
  int       err;
  int       listen_sd;
  int       sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  socklen_t    client_len;
  SSL_CTX*  ctx;
  SSL*      ssl;
  X509*     client_cert;
  char*     str;
  char      buf [4096];
  SSL_METHOD const *meth;
  
  /* SSL preliminaries. We keep the certificate and key with the context. */

  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  meth = TLSv1_2_method();
  
  ctx = SSL_CTX_new (meth);
  
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }
  
  if (SSL_CTX_use_certificate_file(ctx, RSA_CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, RSA_KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }

  if (SSL_CTX_use_second_certificate_file(ctx, ECDH_CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_second_PrivateKey_file(ctx, ECDH_KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_second_private_key(ctx)) {
    fprintf(stderr,"Second private key does not match the certificate public key\n");
    exit(5);
  }

  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
  
  memset(&sa_serv, 0, sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons (1111);          /* Server Port number */
  
  err = bind(listen_sd, (struct sockaddr*) &sa_serv,
	     sizeof (sa_serv));                   CHK_ERR(err, "bind");
	     
  /* Receive a TCP connection. */
	     
  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
  
  client_len = sizeof(sa_cli);
  sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
  CHK_ERR(sd, "accept");
  close (listen_sd);

  printf ("Connection from %lx, port %x\n",
	  sa_cli.sin_addr.s_addr, sa_cli.sin_port);
  
  /* ----------------------------------------------- */
  /* TCP connection is ready. Do server side SSL. */

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);     /* CHECKED */
  SSL_set_fd (ssl, sd);
  err = SSL_accept (ssl);                        CHK_SSL(err);      /* CHECKED */
  
  /* Get the cipher - opt */
  
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  printf ("SSL connection using %s\n", SSL_get_sec_cipher (ssl));
  
  /* Get client's certificate (note: beware of dynamic allocation) - opt */

  client_cert = SSL_get_peer_certificate (ssl);
  if (client_cert != NULL) {
    printf ("Client certificate:\n");
    
    str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t subject: %s\n", str);
    OPENSSL_free (str);
    
    str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t issuer: %s\n", str);
    OPENSSL_free (str);
    
    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */
    
    X509_free (client_cert);
  } else
    printf ("Client does not have certificate.\n");

  /* DATA EXCHANGE - Receive message and send reply. */
   
  /*
  FILE *fileptr;
  char *buffer;
  long filelen;

  fileptr = fopen("test1Gb.txt", "rb");     // Open the file in binary mode
  fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
  filelen = ftell(fileptr);             // Get the current byte offset in the file
  rewind(fileptr);                      // Jump back to the beginning of the file

  buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
  fread(buffer, filelen, 1, fileptr);                // Read in the entire file
  fclose(fileptr);                                   // Close the file
  
  */
  
  err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
  buf[err] = '\0';
  printf ("Got %d chars:'%s'\n", err, buf);
  
  err = SSL_write (ssl, "I hear you.", strlen("I hear you."));  CHK_SSL(err);
  
  /*int max_size = 16250;
  err = 0;
  int total_size = max_size;
  
  while(total_size < filelen){
    err = SSL_write (ssl, buffer+err, max_size);  CHK_SSL(err);
    total_size += err;
  }
  
  // SSL_write (ssl, buffer, filelen - total_size);
  
  printf("test1Gb.txt filelen = %ld\n", filelen);*/

  /* Clean up. */

  // free(buffer);
  
  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
  
  return 0;
  
}
/* EOF - serv.cpp */ 
