CXXFLAGS =	-O2 -g -Wall -fmessage-length=0

OBJS =		NSHW3.o	ssl_helper.o GLOBAL.o  HttpHeaderParser.o

LIBS = -lpthread -lssl -lcrypto

TARGET =	NSHW3

$(TARGET):	$(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LIBS)

all:	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
