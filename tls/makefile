TARGET=TestOpenSSL
SRC=$(wildcard ./*.cpp ./tls/*.cpp) 
OBJS = $(patsubst %.cpp,%.o,$(SRC))
LIBS= -lssl -lcrypto
$(TARGET):$(OBJS)
	g++ $+ -o $@ $(LIBS)
clean:
	rm $(OBJS) $(TARGET)