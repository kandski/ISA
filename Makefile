CXX=g++
CXXFLAGS=-c -pedantic -std=c++11
INCLUDES=-I/usr/local/opt/openssl/include 
LIBS= -lssl -lcrypto -L/usr/local/opt/openssl/lib
SRC = $(wildcard *.cpp)
OBJ = $(patsubst %.cpp, %.o, $(SRC))

all: popcl 

popcl: mySocket.o mySecuredSocket.o main.o argparser.o
	$(CXX) $(INLUDES) -o popcl mySocket.o mySecuredSocket.o main.o argparser.o $(LIBS)

argparser.o: argparser.cpp argparser.h 
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c argparser.cpp

mySocket.o: mySocket.cpp mySocket.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c mySocket.cpp

mySecuredSocket.o: mySecuredSocket.cpp mySecuredSocket.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c mySecuredSocket.cpp

main.o:	main.cpp argparser.h mySocket.h mySecuredSocket.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c main.cpp
clean:
	rm -f *.o popcl *.out *.h.gch
zip:
	
