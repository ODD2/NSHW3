/*
 * HttpHeaderParser.cpp
 *
 *  Created on: Apr 5, 2020
 *      Author: xd
 */

#include "HttpHeaderParser.h"
#include "GLOBAL.h"

HttpHeaderParser::HttpHeaderParser(int client, SSL *ssl, char *headerBuffer) {
	string headerRaw(headerBuffer);
	string firstLine;
	string optLines;
	string contents;
//	seperate the first line
	{
		size_t pos;
		if ((pos = headerRaw.find("\r\n")) == string::npos)
			throw "Header Format Error";

		firstLine = headerRaw.substr(0, pos);
		headerRaw = headerRaw.substr(pos + 2);
	}
// seperate the options and contents
	{
		size_t pos, prev_pos = 0;
		while (1) {
			pos = headerRaw.find("\r\n", prev_pos);
			if (pos == string::npos)
				throw "Header Format Error";
			else if (prev_pos == pos) {
				optLines = headerRaw.substr(0, prev_pos);
				contents = headerRaw.substr(pos + 2);
				break;
			} else
				prev_pos = pos + 2;
		}
	}

	parseFirstLine(firstLine);
	parseOptions(optLines);

	// fetch the contents
	{
		if (optPair.count("Content-Length")) {

			char buffer[BUF_LEN] = { 0 };
			size_t length = strtoll(optPair["Content-Length"].c_str(), NULL, 10);
			int epollfd = epoll_create1(0);
			int nfds = 0;

			if (epollfd == -1) {
				PERROR("Cannot Create Epollfd")
				exit(EXIT_FAILURE);
			}
			epoll_event ev, ready_events[MAX_EPOLL_EVENTS];
			{
				ev.events = EPOLLIN | EPOLLOUT;
				ev.data.fd = client;
				if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client, &ev) == -1) {
					PERROR("Cannot Add Client FD Into Epoll");
					exit(EXIT_FAILURE);
				}
			}

			while (contents.length() < length) {
				nfds = epoll_wait(epollfd, ready_events, MAX_EPOLL_EVENTS, -1);
				if (nfds == -1) {
					PERROR("Epoll wait error.")
					exit(EXIT_FAILURE);
				}
				for (int n = 0; n < nfds; ++n) {
					int ready_fd = ready_events[n].data.fd;
					unsigned int code = ready_events[n].events;

					//Check fd event code
					if ((code & EPOLLERR) || (code & EPOLLRDHUP) || (code & EPOLLHUP)) {
						PINFO("Connection Closed. Ending Service. (fd:"<<ready_fd<<")")
						goto EPOLL_END;
					}

					if (ready_fd == client && (code & EPOLLIN)) {
						int read = SSL_read(ssl, buffer, length - contents.length());
						if (read == 0)
							goto EPOLL_END;
						contents += buffer;
					}
				}
			}
			EPOLL_END:
			PINFO("Content Fetched. Content Tmp == Content-Length ? " << (contents.size()==length))
		}
	}
	mContent = move(contents);
}
;

map<string, string>& HttpHeaderParser::getOptions() {
	return optPair;
}

string HttpHeaderParser::getPath() {
//	PINFO(mUrl)
	return mUrl;
}

string HttpHeaderParser::getFile() {
//	PINFO(mUrl.substr(mUrl.rfind("/") + 1));
	return mUrl.substr(mUrl.rfind("/") + 1);
}

string HttpHeaderParser::getDirectory() {
//	PINFO(mUrl.substr(0, mUrl.rfind("/")));
	return mUrl.substr(0, mUrl.rfind("/"));
}

eMethod HttpHeaderParser::getMethod() {
//	PINFO(reqMethod)
	return reqMethod;
}

string HttpHeaderParser::getContent() {
//	PINFO(mContent)
	return mContent;
}

string HttpHeaderParser::getQuery() {
//	PINFO(mQuery)
	return mContent;
}

string HttpHeaderParser::getParams() {
	string ret = "";
	switch (reqMethod) {
	case eMethod::Get:
		ret = mQuery;
		break;
	case eMethod::Post:
		ret = mContent;
		break;
	default:
		break;
	}
//	PINFO(ret)
	return ret;
}

void HttpHeaderParser::parseFirstLine(string firstLine) {
	//	Get Method
	{
		size_t pos = firstLine.find(" ");
		if (pos == string::npos)
			throw "Header Format Error";
		string method = firstLine.substr(0, pos);
		if (method == "GET") {
			reqMethod = eMethod::Get;
		} else if (method == "POST") {
			reqMethod = eMethod::Post;
		} else
			throw "Unknown Method";

		firstLine = firstLine.substr(pos + 1);
	}
	// Get URL
	{
		size_t pos = firstLine.find(" ");
		if (pos == string::npos)
			throw "Header Format Error";
		string url = firstLine.substr(0, pos);

		//	Get query string if method is GET
		if (reqMethod == eMethod::Get) {
			pos = url.find("?");
			if (pos != string::npos) {
				mQuery = url.substr(pos + 1);
				url = url.substr(0, pos);
			}
		}

		//	Check if Url  has relative path
		if (url.find("../") != string::npos) {
			throw "Invalid Url with relative path";
		}

		//Check if Url request default index.html
		if (url.back() == '/') {
			url.append("index.html");
		}

		mUrl = url;
	}
}

void HttpHeaderParser::parseOptions(string optLines) {
	size_t pos = 0, prev_pos = 0, comma = 0;
	string option;
	while ((pos = optLines.find("\r\n", prev_pos)) != string::npos) {
		option = optLines.substr(prev_pos, pos - prev_pos);
		//Unknown Option Format Ignoring.
		if ((comma = option.find(":")) == string::npos)
			continue;
		//Seperate key and value
		optPair[option.substr(0, comma)] = option.substr(comma + 1);
		prev_pos = pos + 2;
	}
}

map<string, string> ParseQuery(string str) {
	PINFO(str)
	char *buf = new char[str.length() + 1];
	memset(buf, '\0', str.length() + 1);
	memcpy(buf, str.c_str(), str.length());
	auto ret = ParseQuery(buf);
	delete[] buf;
	return ret;
}

map<string, string> ParseQuery(char *buffer) {
	PINFO(buffer)
	map<string, string> ret;
	char *line = strtok(buffer, "&");
	string id, value;
	size_t split;

	while (line != NULL) {
		id = line;
		split = id.find('=');
		//if input format incorrect, DROP.
		if (split != string::npos) {
			//save key/value pair
			value = id.substr(split + 1);
			id = id.substr(0, split);
			ret[id] = urldecoder(value);
			PINFO(id << "," << value)
		}
		//get next line
		line = strtok(NULL, "&");
	}
	return ret;
}

string urldecoder(string query) {
	char *dst = new char[query.length() + 1];
	char a, b;
	int i_s = 0, i_d = 0;
	for (int j = query.length(); i_s < j;) {
		if ((query[i_s] == '%') && ((a = query[i_s + 1]) && (b = query[i_s + 2])) && (isxdigit(a) && isxdigit(b))) {
			if (a >= 'a')
				a -= 'a' - 'A';
			else if (a >= 'A')
				a -= ('A' - 10);
			else
				a -= '0';
			if (b >= 'a')
				b -= 'a' - 'A';
			else if (b >= 'A')
				b -= ('A' - 10);
			else
				b -= '0';
			dst[i_d++] = 16 * a + b;
			i_s += 3;
		} else if (query[i_s] == '+') {
			dst[i_d++] = ' ';
			++i_s;
		} else {
			dst[i_d++] = query[i_s++];
		}
	}
	dst[i_d] = '\0';
	string ret = dst;
	delete[] dst;
	return ret;
}

string html_lineup(string content) {
	string ret = "";
	for (auto i = content.begin(), j = content.end(); i != j; i++) {
		if( (*i)=='\n'){
			ret += "<br>";
		}
		else {
			ret += *i;
		}
	}
	return ret;
}
