CC=g++
CDEFINES=
SOURCES=Dispatcher.cpp address-miner.cpp hexadecimal.cpp ModeFactory.cpp Speed.cpp sha3.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=address-miner.x64

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LDFLAGS=-framework OpenCL
	CFLAGS=-c -std=c++11 -Wall -O2 -g
else
	LDFLAGS=-s -lOpenCL -mcmodel=large
	CFLAGS=-c -std=c++11 -Wall -mmmx -O2 -mcmodel=large -g
endif

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $(CDEFINES) $< -o $@

clean:
	rm -rf *.o

