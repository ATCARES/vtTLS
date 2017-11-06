/*
 * sknock.c
 *
 *  Created on: Nov 6, 2017
 *      Author: Sree Harsha Totakura <sreeharsha@totakura.in>
 *
 *  Original code: Sree Totakura
 *  sknock module: Miguel Pardal
 */

#include "sknock.h"

int sknock_init() {
	int err = 0;
	err = knock_init();
	if (0 != err) {
		fprintf(stderr, "Failed to initialize libknock; "
				"check your sKnock installation and PYTHONPATH\n");
		return err;
	}
	return 0;
}

int knock_try(const char *ip, unsigned short port) {
	struct KNOCK_Handle *kh;

	kh = NULL;
	kh = knock_new(10, 1, 0,
	KNOCK_SERVER_CERT_PATH,
	KNOCK_CLIENT_CERT_PATH,
	KNOCK_CLIENT_CERT_PASSWD);
	if (NULL == kh) {
		return -1;
	}
	return knock_knock(kh, ip, port, 1);
}

int sknock_connect(int socket, struct sockaddr* addr, socklen_t length) {
	int err = 0;
	struct timespec sleep_ns;
	unsigned int retries;

	sleep_ns.tv_sec = KNOCK_WAIT_MS / 1000;
	sleep_ns.tv_nsec = 1000 * 1000 * (KNOCK_WAIT_MS % 1000);

	// convert IP address to string
	struct sockaddr_in* in_addr = (struct sockaddr_in*) addr;
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(in_addr->sin_addr), ip, INET_ADDRSTRLEN);
	int port = ntohs(in_addr->sin_port);
	printf("ip %s port %d\n", ip, port);

	for (retries = 0; retries < KNOCK_RETRIES; retries++) {
		err = connect(socket, addr, length);
		if (0 == err) {
			// break;
			return 0;
		}
		// The connect may have failed because the port may have to be knocked
		if ((ECONNREFUSED != errno) && (ETIMEDOUT != errno)
				&& (ECONNRESET != errno)) {
			fprintf(stderr, "Cannot open a connection to destination: %s\n",
					strerror(errno));
			return errno;
		}
		if (-1 == knock_try(ip, port)) {
			fprintf(stderr, "Failed to create sknock handle\n");
			return -1;
		}
		fprintf(stderr, "Knock request sent\n");
		if (-1 == nanosleep(&sleep_ns, NULL)) {
			return -2;
		}
	}

	if (KNOCK_RETRIES == retries) {
		fprintf(stderr, "Could not connect after %u retires with knocking.\n",
				retries);
		return -3;
	}

	// no error
	return 0;
}
