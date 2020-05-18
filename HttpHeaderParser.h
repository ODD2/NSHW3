#ifndef HttpHeaderParserOD
#define HttpHeaderParserOD
#include <vector>
#include <string>
#include <exception>
#include <string.h>
#include <string>
#include <iostream>
#include <map>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
enum eMethod {
	Unknown = -1, Get, Post, Total,
};

class HttpHeaderParser {
public:
	HttpHeaderParser(int, SSL*, char*);

	string getPath();

	string getFile();

	string getDirectory();

	string getContent();

	string getQuery();

	string getParams();

	map<string, string>& getOptions();

	eMethod getMethod();

private:
	void parseFirstLine(string firstLine);
	void parseOptions(string optLines);

	eMethod reqMethod = eMethod::Unknown;
	map<string, string> optPair;
	string mUrl = "";
	string mQuery = "";
	string mContent = "";
};

map<string, string> ParseQuery(char *buffer);
map<string,string> ParseQuery(string str);

string urldecoder(string src);

string html_lineup(string content);
#endif
