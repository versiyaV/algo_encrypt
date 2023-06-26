CPP_FLAGS = -Wall -Wextra -O2 -std=c++17

all: example

clean:
	rm -rf bin/

example: example.cpp
	g++ $^ -c -o $@ $(CPP_FLAGS)
