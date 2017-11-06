/*
 * sknock.h
 *
 *  Created on: Nov 6, 2017
 *      Author: Sree Harsha Totakura <sreeharsha@totakura.in>
 *
 *  Original code: Sree Totakura
 *  sknock module: Miguel Pardal
 */

#ifndef SKNOCK_VTTLS_CLIENT_H_
#define SKNOCK_VTTLS_CLIENT_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

#include <knock.h>

/* Hard-coded values for certificates used for knocking */
#define KNOCK_SERVER_CERT_PATH "knock_server.cer"
#define KNOCK_CLIENT_CERT_PATH "knock_client.pfx"
#define KNOCK_CLIENT_CERT_PASSWD "portknocking"

/* Time in milliseconds we sleep after sending a knock request */
#define KNOCK_WAIT_MS 250

/* How many times do we try to knock? */
#define KNOCK_RETRIES 3

/**
 * Initialize sKnock
 */
int sknock_init();

/**
 * Try to knock
 *
 * @param ip the IP addresses of the server to connect as a string
 * @param port the port which has to be knocked
 * @return -1 upon error; 0 on failure; 1 on success
 */
int sknock_try(const char *ip, unsigned short port);

/**
 * Connect to a socket. If connection is refused, perform (multiple) sKnock.
 */
int sknock_connect(int socket, struct sockaddr* addr, socklen_t length);

#endif /* SKNOCK_VTTLS_CLIENT_H_ */
