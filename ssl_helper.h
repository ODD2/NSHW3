/*
 * ssl_helper.h
 *
 *  Created on: Apr 27, 2020
 *      Author: xd
 */

#ifndef SSL_HELPER_H_
#define SSL_HELPER_H_
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//initialize ssl
void init_openssl();

//clean up ssl
void cleanup_openssl(SSL_CTX* ctx);

//create context for ssl
SSL_CTX* create_context();

//configure the context for ssl
void configure_context(SSL_CTX*, const char[], const char[]);

void close_ssl(SSL* ssl);

//the verification call back. called during verification, prints issuer and subject information.
int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);

//get error message  according to the result of SSL_get_verify_result()
const char* get_validation_errstr(long e);

#endif /* SSL_HELPER_H_ */
