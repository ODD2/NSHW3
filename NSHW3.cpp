//============================================================================
// Name        : NSHW3.cpp
// Author      : ODD2
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C, Ansi-style
//============================================================================

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <iostream>
#include <fstream>
#include <thread>
#include <csignal>
#include <map>
#include <chrono>
#include <wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "HttpHeaderParser.h"
#include "GLOBAL.h"
#include "ssl_helper.h"
using namespace std;

#define SimplePage( x ) \
		"<form action=\"/\" method=\"POST\">>"\
			"<input type=\"text\" placeholder=\"Command\" name=\"cmd\">"\
			"<input type=\"submit\" value=\"Submit\">"\
		"</form>" \
		"<div>" + (string)( x ) + "</div>"

void test_tls_handler(int client_socket);
void http_handler(int);
void file_handler(int, HttpHeaderParser&);
void cgi_handler(int, HttpHeaderParser&);
int socket_driver(SSL *ssl, int client, int child_pid, int (&S2B)[2], int (&B2S)[2]);
void bash_driver(int (&S2B)[2], int (&B2S)[2]);
void html_404_handler(int, const char*);
void http_sender(int dest_socket, std::map<string, string> header_options);
void https_sender(SSL *ssl, std::map<string, string> header_options);
string create_https_response(std::map<string, string> header_options);
int client_handler(int client, SSL_CTX *ctx);

string get_http_time() {
	char buf[30];
	time_t now = time(0);
	tm tm = *gmtime(&now);
	strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S %Z", &tm);
	return buf;
}

int create_listen(const char listen_ip[], int port) {
	int s;
	struct sockaddr_in addr;
	int opt = 1;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(listen_ip);

	s = socket(AF_INET, SOCK_STREAM, 0);

	if (s < 0) {
		PERROR("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(s, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		PERROR("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(s, 1) < 0) {
		PERROR("Unable to listen");
		exit(EXIT_FAILURE);
	}

	PINFO("Start Listening. (IP:" << listen_ip << ", PORT:" << port << ")")
	return s;
}

int main(int argc, char const *argv[]) {
	int listen;
	struct sockaddr_in in_addr;
	uint in_len = sizeof(in_addr);
	SSL_CTX *ctx = NULL;

	//Setup Openssl Prerequisites
	init_openssl();
	ctx = create_context();
	configure_context(ctx, "./server/cert.pem", "./server/key.pem");

	//Setup socket server
	listen = create_listen(TLS_SERVER_IP, TLS_SERVER_PORT);

	//Handle connections
	while (1) {
		int client = accept(listen, (struct sockaddr*) &in_addr, &in_len);

		if (client < 0) {
			PERROR("Unable to accept.");
		} else {
			PINFO("New Client! (fd:" << client << ")")

			//do fork
			switch (forkm()) {
			case -1:
				PERROR("Failed to Fork")
				exit(EXIT_FAILURE);
				break;
			case 0:
				//client ignore server socket
				close(listen);
				//Service
				exit(client_handler(client, ctx));
				break;
			default:
				//server ignore client socket
				close(client);
				break;
			}
		}
	}

	cleanup_openssl(ctx);
	close(listen);
	PINFO("Listen Closed. (fd:" << listen << ")")
	return 0;
}

int client_handler(int client, SSL_CTX *ctx) {
	int ret = 0;

	SSL *ssl = SSL_new(ctx);

	SSL_set_fd(ssl, client);

	if (SSL_accept(ssl) <= 0) {
		PERROR("SSL Accept Error.");
		ERR_print_errors_fp(stderr);
		ret = -1;
	} else {
		PINFO("SSL Accepted.");
//		SSL_write(ssl, "BEGIN SSL", 9);
//		https_sender(ssl, { { "Content", "Testing HTTPS Connection", } });

		int S2B[2], B2S[2];
		//Create pipe for bash
		if (pipe(S2B) < 0 || pipe(B2S) < 0) {
			PERROR("Cannot Create Pipeline For Bash");
			exit(EXIT_FAILURE);
		}

		int child_pid;
		switch (child_pid = forkm()) {
		case -1:
			PERROR("Cannot Create Child Process")
			exit(EXIT_FAILURE);
			break;
		case 0:
			close(client);

			bash_driver(S2B, B2S);
			exit(0);
			break;
		default:
			socket_driver(ssl, client, child_pid, S2B, B2S);
			break;
		}

		close_ssl(ssl);
		close(client);
		PINFO("Connection Closed. (fd:" << client << ")")
		return ret;
	}
	return 0;
}

void bash_driver(int (&S2B)[2], int (&B2S)[2]) {
	//close socket send,and  socket receive fd;
	//S2B = > socket send[1] -> bash receive[0]
	//B2S = > bash send[1] -> socket receive[0]
	close(S2B[1]);
	close(B2S[0]);

	dup2(B2S[1], STDOUT_FILENO);
	dup2(B2S[1], STDERR_FILENO);
	dup2(S2B[0], STDIN_FILENO);

	close(S2B[0]);
	close(B2S[1]);

	execlp("bash", "/bin/bash", NULL);
	exit(0);
}

int socket_driver(SSL *ssl, int client, int child_pid, int (&S2B)[2], int (&B2S)[2]) {
	//close bash send and  bash receive fd;
	close(S2B[0]);
	close(B2S[1]);

	int epollfd = epoll_create1(0);
	if (epollfd == -1) {
		PERROR("Cannot Create Epollfd")
		exit(EXIT_FAILURE);
	}
	epoll_event ev, ready_events[MAX_EPOLL_EVENTS];
//	Register fd to poll
	{
		ev.events = EPOLLOUT;
		ev.data.fd = S2B[1];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, S2B[1], &ev) == -1) {
			PERROR("Cannot Add Shell to Bash FD Into Epoll");
			exit(EXIT_FAILURE);
		}
	}

	{
		ev.events = EPOLLIN;
		ev.data.fd = B2S[0];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, B2S[0], &ev) == -1) {
			PERROR("Cannot Add Shell to Bash FD Into Epoll");
			exit(EXIT_FAILURE);
		}
	}

	{
		ev.events = EPOLLIN | EPOLLOUT;
		ev.data.fd = client;
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client, &ev) == -1) {
			PERROR("Cannot Add Client FD Into Epoll");
			exit(EXIT_FAILURE);
		}
	}

	//operation
	int nfds = 0;
	string str_s2c = "";
	string str_s2b = "";
	char buffer[BUF_LEN] = { 0 };
	int progress = 0;
	int wait_bash_round = 0;
	PINFO("S2B[1]:" << S2B[1] << ", B2S[0]:" << B2S[0] << ", Client:" << client)
	while (1) {
		nfds = epoll_wait(epollfd, ready_events, MAX_EPOLL_EVENTS, -1);
		if (nfds == -1) {
			PERROR("Epoll wait error.")
			exit(EXIT_FAILURE);
		}
		ssize_t read_size, send_size, total_size;
		for (int n = 0; n < nfds; ++n) {
			int ready_fd = ready_events[n].data.fd;
			unsigned int code = ready_events[n].events;
			//PINFO("Socket Ready:" <<ready_fd)

			//Check fd event code
			if ((code & EPOLLERR) || (code & EPOLLRDHUP) || (code & EPOLLHUP)) {
				PINFO("Connection Closed. Ending Service. (fd:"<<ready_fd<<")")
				goto EPOLL_END;
			}

			//
			if (progress == 1 && ready_fd == S2B[1]) {
				total_size = str_s2b.length();
				send_size = write(S2B[1], str_s2b.c_str(), total_size);
				if (send_size < total_size) {
					PINFO("Client command sent to bash. : ["<< str_s2b.substr(0,send_size) << "]")
					str_s2b.substr(send_size);
				} else if (send_size == total_size) {
					PINFO("Client command sent to bash. : ["<< str_s2b << "]")
					str_s2b = "";
					progress = 2;
				}
			} else if (progress == 2) {
				if (ready_fd == B2S[0]) {
					memset(buffer, '\0', BUF_LEN);
					read_size = read(ready_fd, buffer, BUF_LEN);
					PINFO("Bash returns content: [" << buffer << "].  (size:" << read_size <<")");
					str_s2c += buffer;
					wait_bash_round = 0;
				} else if (wait_bash_round > 10) {
					wait_bash_round = 0;
					str_s2c = create_https_response( { { "Status", "200 OK" }, { "Content", SimplePage(html_lineup(str_s2c.length()==0?"Timeout!!":str_s2c)) } });
					progress = 3;
				} else {
					usleep(100000);
					++wait_bash_round;
				}

			} else if ((progress == 0 || progress == 3) && ready_fd == client) {
				if ((progress == 0 && code & EPOLLIN) > 0) {
					//clean buffer
					memset(buffer, '\0', BUF_LEN);
					read_size = SSL_read(ssl, buffer, BUF_LEN);
					if (read_size == 0) {
						goto EPOLL_END;
					}
					HttpHeaderParser parser(client, ssl, buffer);

					auto query = ParseQuery(parser.getParams());
					str_s2b += query["cmd"] + "\n";
					progress = 1;
					PINFO("Client command received: [" << query["cmd"]<< "] (size:" << parser.getParams().length() << ")");
//					super weird condition.
//					epoll told me there were data in file descriptor, but read nothing.
//					suppose this descriptor is broken?
//					even the event codes above didn't detect the error.

				}
				if (progress == 3 && (code & EPOLLOUT) > 0) {
					total_size = str_s2c.length();
					send_size = SSL_write(ssl, str_s2c.c_str(), total_size);
					if (send_size < total_size) {
						str_s2c.substr(send_size);
						PINFO("Bash return sent partial data to client.");
					} else if (send_size == total_size) {
						PINFO("Bash return sent to client: [" << str_s2c <<"]");
						str_s2c = "";
						progress = 0;
						PINFO("Progress Set to 0");
					}
				}
			}
		}
	}
	EPOLL_END:
	PINFO("Closing PINFO");
	write(S2B[1], "exit\n", 4);
	close(epollfd);
	return 0;
}

//void http_handler(int client_socket) {
//	char buffer[BUF_LEN] = { 0 };
//	int read_count = 0;
//	//select() requirements.
//	fd_set rset;
//	//	{secs, usecs}
//	timeval tv = { KEEP_ALIVE_TIMEOUT, 0 };
//
//	//setup
//	FD_ZERO(&rset);
//
//	while (1) {
//		try {
//			//watch client_socket
//			FD_SET(client_socket, &rset);
//
//			int readyN = select(client_socket + 1, &rset, NULL, NULL, &tv);
//			//if timeout or error
//			if (readyN <= 0)
//				throw EC_CON_TIMEOUT;
//			//if client_socket has event
//			else if (FD_ISSET(client_socket, &rset)) {
//				read_count = recv(client_socket, buffer, BUF_LEN, MSG_DONTWAIT);
//				//nothing to read
//				if (read_count == -1)
//					continue;
//				//connection closed
//				else if (read_count == 0)
//					break;
//
//				PINFO("Http Request:\n"<< buffer <<endl)
//				HttpHeaderParser parser(client_socket, buffer);
//				if (parser.getFile().find("cgi") != string::npos)
//					cgi_handler(client_socket, parser);
//				else
//					file_handler(client_socket, parser);
//			}
//		} catch (const char *msg) {
//			PINFO("Send 404.")
//			html_404_handler(client_socket, msg);
//		} catch (int errorCode) {
//			if (errorCode == EC_CON_TIMEOUT) {
//				PINFO("Connection Overtime.")
//				break;
//			} else if (errorCode == EC_CON_CLOSE) {
//				PINFO("Connection Closed By Client.")
//				break;
//			} else {
//				http_sender(client_socket,
//						{ { "Status", "500 Internal Server Error" }, { "Content", "Unknown Error" } });
//			}
//		} catch (...) {
//			PINFO("Send 500.")
//			http_sender(client_socket, { { "Status", "500 Internal Server Error" }, { "Content", "Server Error" } });
//			break;
//		}
//		memset(buffer, '\0', BUF_LEN);
//	}
//
//	close(client_socket);
//	PINFO("<!Socket Closed!>")
//}

void http_sender(int dest_socket, std::map<string, string> header_options) {
	string ret = "HTTP/1.1 " + (header_options.count("Status") ? header_options["Status"] : "404 Not Found") + "\r\n"
	CONNECTION_OPTION
	"Date: " + get_http_time() + "\r\n"
			"Expires: -1\r\n"
			"Server: NSHW1_EZHTTPD\r\n"
			"Cache-Control: private, max-age=0\r\n"
			"Content-Type:" + (header_options.count("Content-Type") ? header_options["Content-Type"] : " text/html; charset=UTF-8") + "\r\n"
			"Content-Length:" + (header_options.count("Content") ? to_string(header_options["Content"].size()) : "0") + " \r\n"
	//Add Custom Header
			+ header_options["Custom"] +
			//Add Content
			"\r\n" + header_options["Content"] + "\r\n";

	//Send Packet
	for (int i = 0, j = ret.size(); i < j; i += BUF_LEN) {
		send(dest_socket, (void*) &ret[i], ((j - i) < BUF_LEN ? j - i : BUF_LEN), 0);
	}

	PINFO("Sent Package:\n" << ret)
}

void https_sender(SSL *ssl, std::map<string, string> header_options) {
	string ret = "HTTP/1.1 " + (header_options.count("Status") ? header_options["Status"] : "404 Not Found") + "\r\n"
	CONNECTION_OPTION
	"Date: " + get_http_time() + "\r\n"
			"Expires: -1\r\n"
			"Server: NSHW1_EZHTTPD\r\n"
			"Cache-Control: private, max-age=0\r\n"
			"Content-Type:" + (header_options.count("Content-Type") ? header_options["Content-Type"] : " text/html; charset=UTF-8") + "\r\n"
			"Content-Length:" + (header_options.count("Content") ? to_string(header_options["Content"].size()) : "0") + " \r\n"
//Add Custom Header
			+ header_options["Custom"] +
//Add Content
			"\r\n" + header_options["Content"] + "\r\n";

	//Send Packet
	for (int i = 0, j = ret.size(); i < j; i += BUF_LEN) {
		SSL_write(ssl, (const void*) &ret[i], ((j - i) < BUF_LEN ? j - i : BUF_LEN));
	}

	PINFO("Sent Package:\n" << ret)
}

string create_https_response(std::map<string, string> header_options) {
	return ("HTTP/1.1 " + (header_options.count("Status") ? header_options["Status"] : "404 Not Found") + "\r\n"
	CONNECTION_OPTION
	"Date: " + get_http_time() + "\r\n"
			"Expires: -1\r\n"
			"Server: www.b10615027.com\r\n"
			"Cache-Control: private, max-age=0\r\n"
			"Content-Type:" + (header_options.count("Content-Type") ? header_options["Content-Type"] : " text/html; charset=UTF-8") + "\r\n"
			"Content-Length:" + (header_options.count("Content") ? to_string(header_options["Content"].size()) : "0") + " \r\n"
	//Add Custom Header
			+ header_options["Custom"] + "\r\n"
			//Add Content
			+ header_options["Content"] + "\r\n");
}

void file_handler(int client_socket, HttpHeaderParser &parser) {
	int file_size = 0;
	string fullPath = ROOT_PATH + parser.getPath();
	PINFO("FullPath:" << fullPath);
	std::fstream infile = std::fstream(fullPath, ios::in | ios::binary);

	if (!infile) {
		PINFO("HTML Handler: Cannot Open FIle.")
		throw "Cannot Open File.";
	}

	infile.seekg(0, infile.end);
	file_size = infile.tellg();
	infile.seekg(0, infile.beg);
	char *buffer = new char[file_size + 1];
	buffer[file_size] = '\0';
	PINFO("File Size:" << file_size)
	infile.read(buffer, file_size);
	infile.close();

	http_sender(client_socket, { { "Status", "200 OK" }, { "Content", buffer } });

	delete[] buffer;
}

void cgi_handler(int client_socket, HttpHeaderParser &parser) {
	PINFO("CGI Handling.");
	string fullPath = ROOT_PATH + parser.getPath();
	if (access(fullPath.c_str(), F_OK) == -1)
		throw "No Cgi File";

	int ParentOutput[2] = { 0 };
	int ChildOutput[2] = { 0 };
	int status;
	pid_t cpid;
	char c;

	/* Use pipe to create a data channel betweeen two process
	 'ParentOutput'  handle  data from 'host' to 'CGI'
	 'ChildOutput' handle data from 'CGI' to 'host'*/
	if (pipe(ParentOutput) < 0 || pipe(ChildOutput) < 0) {
		throw "Cannot Execute Cgi. Cannot CreatePipe.";
	}

	/* Creates a new process to execute cgi program */
	if ((cpid = fork()) < 0) {
		throw "Cannot Execute Cgi. Fork Failed.";
	}

	/*child process*/
	if (cpid == 0) {
		//close unused fd
		close(ParentOutput[1]);
		close(ChildOutput[0]);

		//redirect the output from stdout to cgiOutput
		dup2(ChildOutput[1], STDOUT_FILENO);

		//redirect the input from stdin to cgiInput
		dup2(ParentOutput[0], STDIN_FILENO);

		//after redirect we don't need the old fd
		close(ParentOutput[0]);
		close(ChildOutput[1]);

		/* execute cgi program
		 the stdout of CGI program is redirect to cgiOutput
		 the stdin  of CGI program is redirect to cgiInput
		 */

		execlp(fullPath.c_str(), fullPath.c_str(), NULL);
		exit(0);
	}

	/*parent process*/
	else {
		//close unused fd
		close(ParentOutput[0]);
		close(ChildOutput[1]);

		// send the message to the CGI program
		string params = parser.getParams();
		int totalSize = params.size();
		for (int i = 0; i < totalSize;) {
			i += write(ParentOutput[1], &params[i], (i + BUF_LEN < totalSize ? BUF_LEN : totalSize - i));
		}

		// receive the message from the  CGI program
		string result = "";
		while (read(ChildOutput[0], &c, 1) > 0) {
			//buffer the message
			result.append(1, c);
		}

		// connection finish
		close(ChildOutput[0]);
		close(ParentOutput[1]);
		waitpid(cpid, &status, 0);
		http_sender(client_socket, { { "Status", "200 OK" }, { "Content", result } });
	}
}

void html_404_handler(int client_socket, const char *msg) {
	http_sender(client_socket, { { "Status", "404 Not Found" }, { "Content", msg } });
}
