/*
 * GLOBAL.h
 *
 *  Created on: Apr 27, 2020
 *      Author: xd
 */

#ifndef GLOBAL_H_
#define GLOBAL_H_
#define DEBUG

#include <stdio.h>
#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/wait.h>
using namespace std;


//PRINTINGS
#define PERROR( x ) cerr << __PRETTY_FUNCTION__ << ": " << x   << endl;

#ifdef DEBUG
#define PINFO( x ) cout << __PRETTY_FUNCTION__ <<  ": " <<  x   << endl;
#endif

//HTTP SETTINGS
#define ROOT_PATH "./public/"
#define CONNECTION_OPTION "Connection: keep-alive\r\n"\
															"Keep-Alive: timeout=5, max=1000\r\n"
#define KEEP_ALIVE_TIMEOUT 5
								  //sec usec
#define CGI_TIMEOUT 1,0


#define EC_CON_TIMEOUT 0
#define EC_CON_CLOSE 1

//BUFFERS
#define BUF_LEN 1024

//NETWORKS
#define TLS_SERVER_PORT 5000
#define TLS_SERVER_IP "127.0.0.1"

//POLLINGS
#define MAX_EPOLL_EVENTS 20

//FUNCTIONS
int forkm();



#endif /* GLOBAL_H_ */
