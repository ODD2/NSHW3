/*
 * ssl_helper.cpp
 *
 *  Created on: Apr 27, 2020
 *      Author: xd
 */

#include "ssl_helper.h"
#include "GLOBAL.h"

void init_openssl() {
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	OpenSSL_add_ssl_algorithms();
	PINFO("SSL Initialized.");
}

void cleanup_openssl(SSL_CTX *ctx) {
	SSL_CTX_free(ctx);
	EVP_cleanup();
	PINFO("SSL Cleaned.");
}

SSL_CTX* create_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	//set method to tls method. equivalent to SSLv23_method();
	method = TLS_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	} else {
		PINFO("SSL Context Created.");
	}
	return ctx;
}

void configure_context(SSL_CTX *ctx, const char cert_loc[],
		const char key_loc[]) {
	//	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	//	SSL_CTX_set_ecdh_auto(ctx, 1);

	//enable verification
//	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);

	//set ca location to /etc/ssl/certs
//	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") == 0) {
//		ERR_print_errors_fp(stderr);
//		exit(EXIT_FAILURE);
//	}

	//set the key and cert
	if (SSL_CTX_use_certificate_file(ctx, cert_loc, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key_loc, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	PINFO("SSL Context Configured.");
}

void close_ssl(SSL *ssl) {
	int err_code = 0;
	SSL_get_error(ssl,err_code);

	if(!( err_code == SSL_ERROR_SYSCALL ||err_code == SSL_ERROR_SSL)){
		PINFO("SSL Shutdown.");
		SSL_shutdown(ssl);
	}

	PINFO("SSL Free.");
	SSL_free(ssl);

}

int verify_callback(int preverify, X509_STORE_CTX *x509_ctx) {
	int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	int err = X509_STORE_CTX_get_error(x509_ctx);
	if (err) {
		PINFO(
				"Verification Error.(depth:"<<depth << ", msg:" << get_validation_errstr(err) << ")")
	} else {
		X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
		char *iname = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
		char *sname = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

		PINFO("Verification Info")
		printf("	Issuer (cn): %s\n", (char*) iname);
		printf("	Subject (cn): %s\n", (char*) sname);
		printf("\n");
	}

	return preverify;
}

const char* get_validation_errstr(long e) {
	switch ((int) e) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		return "ERR_UNABLE_TO_GET_ISSUER_CERT";
	case X509_V_ERR_UNABLE_TO_GET_CRL:
		return "ERR_UNABLE_TO_GET_CRL";
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		return "ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
		return "ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		return "ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		return "ERR_CERT_SIGNATURE_FAILURE";
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		return "ERR_CRL_SIGNATURE_FAILURE";
	case X509_V_ERR_CERT_NOT_YET_VALID:
		return "ERR_CERT_NOT_YET_VALID";
	case X509_V_ERR_CERT_HAS_EXPIRED:
		return "ERR_CERT_HAS_EXPIRED";
	case X509_V_ERR_CRL_NOT_YET_VALID:
		return "ERR_CRL_NOT_YET_VALID";
	case X509_V_ERR_CRL_HAS_EXPIRED:
		return "ERR_CRL_HAS_EXPIRED";
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		return "ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		return "ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		return "ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
		return "ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
	case X509_V_ERR_OUT_OF_MEM:
		return "ERR_OUT_OF_MEM";
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		return "ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		return "ERR_SELF_SIGNED_CERT_IN_CHAIN";
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		return "ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		return "ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		return "ERR_CERT_CHAIN_TOO_LONG";
	case X509_V_ERR_CERT_REVOKED:
		return "ERR_CERT_REVOKED";
	case X509_V_ERR_INVALID_CA:
		return "ERR_INVALID_CA";
	case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		return "ERR_PATH_LENGTH_EXCEEDED";
	case X509_V_ERR_INVALID_PURPOSE:
		return "ERR_INVALID_PURPOSE";
	case X509_V_ERR_CERT_UNTRUSTED:
		return "ERR_CERT_UNTRUSTED";
	case X509_V_ERR_CERT_REJECTED:
		return "ERR_CERT_REJECTED";
	case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
		return "ERR_SUBJECT_ISSUER_MISMATCH";
	case X509_V_ERR_AKID_SKID_MISMATCH:
		return "ERR_AKID_SKID_MISMATCH";
	case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
		return "ERR_AKID_ISSUER_SERIAL_MISMATCH";
	case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
		return "ERR_KEYUSAGE_NO_CERTSIGN";
	case X509_V_ERR_INVALID_EXTENSION:
		return "ERR_INVALID_EXTENSION";
	case X509_V_ERR_INVALID_POLICY_EXTENSION:
		return "ERR_INVALID_POLICY_EXTENSION";
	case X509_V_ERR_NO_EXPLICIT_POLICY:
		return "ERR_NO_EXPLICIT_POLICY";
	case X509_V_ERR_APPLICATION_VERIFICATION:
		return "ERR_APPLICATION_VERIFICATION";
	default:
		return "ERR_UNKNOWN";
	}
}

