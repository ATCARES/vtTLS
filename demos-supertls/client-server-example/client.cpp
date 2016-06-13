#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <iostream>

#include <supertls/crypto.h>
#include <supertls/x509.h>
#include <supertls/pem.h>
#include <supertls/ssl.h>
#include <supertls/err.h>

/* define HOME to be dir for key and cert files... */
#define HOME "./"

#define MAX_MSG_SIZE 16250

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main (int argc, char* argv[])
{
  int       err;
  int       sd;
  struct    sockaddr_in sa;
  SSL_CTX*  ctx;
  SSL*      ssl;
  X509*     server_cert;
  X509*		server_sec_cert;
  char*     str;
  char      buf [4096];
  SSL_METHOD const *meth;
  timeval start, end;


  if(argc != 4){
    printf("Usage: ./client <server-ip> <server-port> <file-to-download>\n");
    exit(0);
  }
  
  
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms(); /* SSL_library_init() */
  meth = TLSv1_2_client_method();
  
  ctx = SSL_CTX_new (meth);
  
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */
  
  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
 
  memset(&sa, 0, sizeof(sa));
  
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = inet_addr (argv[1]);   /* Server IP */
  // sa.sin_addr.s_addr = inet_addr ("172.17.39.8");   /* Server IP */
  sa.sin_port        = htons     (atoi(argv[2]));          /* Server Port number */
  
  err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));                   CHK_ERR(err, "connect");

  /* ----------------------------------------------- */
  /* Now we have TCP conncetion. Start SSL negotiation. */
  
  ssl = SSL_new (ctx);                         CHK_NULL(ssl);
  
  SSL_set_fd (ssl, sd);
  /* Sets the file descriptor fd as the input/output
   * facility for the TLS encypted side
   * of argument "ssl"; fd is usually the socket descriptor */
  
  unsigned long long diff;
  int i = 0;
  
  gettimeofday(&start, NULL);
  
  err = SSL_connect (ssl);                     CHK_SSL(err);
  
  gettimeofday(&end, NULL);
  diff = 1000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000;
  // printf ("The SuperTLS Handshake took %llu ms\n", diff);
  diff = 0;
  
  /* ssl->method->ssl_connect(s)*/
    
  /* Following two steps are optional and not required for
     data exchange to be successful. */
  
  /* Get the cipher - opt */

  /*
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  printf ("SSL connection using %s\n", SSL_get_sec_cipher (ssl));
  */
  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */
  /*
  server_cert = SSL_get_peer_certificate (ssl);       			 CHK_NULL(server_cert);
  
  server_sec_cert = SSL_get_second_peer_certificate (ssl);       CHK_NULL(server_sec_cert);
  
  printf ("Server certificate:\n");
  
  str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t subject: %s\n", str);
  OPENSSL_free (str);

  str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t issuer: %s\n", str);
  OPENSSL_free (str);

  printf ("Server second certificate:\n");

  str = X509_NAME_oneline (X509_get_subject_name (server_sec_cert),0,0);
  CHK_NULL(str);
  printf ("\t subject: %s\n", str);
  OPENSSL_free (str);

  str = X509_NAME_oneline (X509_get_issuer_name  (server_sec_cert),0,0);
  CHK_NULL(str);
  printf ("\t issuer: %s\n", str);
  OPENSSL_free (str);
  */
  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */
/*
  X509_free (server_cert);
  X509_free (server_sec_cert);
  */
  /* --------------------------------------------------- */
  /* DATA EXCHANGE - Send a message and receive a reply. */

  err = SSL_write (ssl, argv[3], strlen(argv[3]));  CHK_SSL(err);
  
  FILE *file_rcv = fopen(argv[3], "ab+");
  file_rcv = fopen(argv[3], "w+");
   
  err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
  buf[err] = '\0';
  // printf ("Got %d chars:'%s'\n", err, buf);
  
  long file_len = strtol(buf, (char**) NULL, 10);
  
  // printf("filelen = %ld\n", file_len);
  
  char *buffer = (char *)malloc((file_len+1)*sizeof(char)); // Enough memory for file + \0
  
  int counter = 0;
  
  for (counter = 0; counter < 50; counter++){
  /*************/
  
    err = 0;
    int total_size = 0;
    i = file_len;
    
    gettimeofday(&start, NULL);
    
    for(i = file_len; i - MAX_MSG_SIZE > 0; i -= MAX_MSG_SIZE){
        err += SSL_read (ssl, buffer+err, MAX_MSG_SIZE);
    }
    
    err += SSL_read (ssl, buffer+err, i);
    
    gettimeofday(&end, NULL);
    diff = 1000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000;
    printf ("%llu\n", diff);
    // printf ("The SuperTLS took %llu ms to read %s.\n", diff, argv[3]);
    diff = 0;
  
  /*************/
  }

  fprintf(file_rcv, "%s", buffer);
  
  // printf("-- total_size: %d\n", err);
  
  SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

  /* Clean up. */

  free(buffer);
  fclose(file_rcv);
  
  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
  
  return 0;
  
}
/* EOF - cli.cpp */
