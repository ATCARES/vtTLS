/* cli.cpp  -  Minimal ssleay client for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* mangled to work with OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

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

#include <vttls/crypto.h>
#include <vttls/x509.h>
#include <vttls/pem.h>
#include <vttls/ssl.h>
#include <vttls/err.h>

#include <knock.h>

/* define HOME to be dir for key and cert files... */
#define HOME "./"

#define MAX_MSG_SIZE 16250
#define DIVERSITY 2

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define KNOCK_SERVER_CERT_PATH "knock_server.cer"
#define KNOCK_CLIENT_CERT_PATH "knock_client.pfx"
#define KNOCK_CLIENT_CERT_PASSWD "portknocking"


/**
 * Try to knock
 *
 * @param ip the IP addresses of the server to connect as a string
 * @param port the port which has to be knocked
 * @return -1 upon error; 0 on failure; 1 on success
 */
int
try_knock (const char *ip, unsigned short port)
{
  struct KNOCK_Handle *kh;

  kh = NULL;
  kh = knock_new(10,
                 2,
                 0,
                 KNOCK_SERVER_CERT_PATH,
                 KNOCK_CLIENT_CERT_PATH,
                 KNOCK_CLIENT_CERT_PASSWD);
  if (NULL == kh)
  {
    return -1;
  }
  return knock_knock(kh,
                     ip,
                     port,
                     1);
}


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
  const char *ip;
  unsigned int port;
  SSL_METHOD const *meth;
  timeval start, end;


  if(argc != 3){
    printf("Usage: ./client <server-ip> <message-to-send>\n");
    exit(0);
  }
  err = knock_init();
  if (0 != err)
  {
    printf("Failed to initialize libknock; "
           "check your sKnock installation and PYTHONPATH\n");
    exit(-1);
  }
  ip = argv[1];
  port = 1111;

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
  sa.sin_addr.s_addr = inet_addr (ip);            /* Server IP */
  sa.sin_port        = htons     (port);          /* Server Port number */

  err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));

  /* The connect may have failed because the port may have to be sKnocked */
  if (-1 == err)
  {
    if (-1 == try_knock(ip, port))
    {
      printf("Failed to create sknock handle\n");
      exit(1);
    }
    err = connect (sd, (struct sockaddr*) &sa,
                   sizeof(sa));
    CHK_ERR(err, "connect");
  }

  /* ----------------------------------------------- */
  /* Now we have TCP connection. Start SSL negotiation. */

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
  printf ("The vtTLS Handshake took %llu ms\n", diff);
  diff = 0;

  /* ssl->method->ssl_connect(s)*/

  /* Following two steps are optional and not required for
     data exchange to be successful. */

  /* Get the cipher - opt */

  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  printf ("SSL connection using %s\n", SSL_get_n_cipher (DIVERSITY, ssl));


  /* Get server's certificate (note: beware of dynamic allocation) - opt */

  server_cert = SSL_get_peer_certificate (ssl);       			 CHK_NULL(server_cert);

  server_sec_cert = SSL_get_n_peer_certificate (DIVERSITY, ssl);       CHK_NULL(server_sec_cert);

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

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */

  X509_free (server_cert);
  X509_free (server_sec_cert);

  /* --------------------------------------------------- */
  /* DATA EXCHANGE - Send a message and receive a reply. */

  err = SSL_write (ssl, argv[2], strlen(argv[2]));  CHK_SSL(err);

  printf("-- total_size: %d\n", err);

  SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

  /* Clean up. */
  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);

  return 0;

}
/* EOF - cli.cpp */
