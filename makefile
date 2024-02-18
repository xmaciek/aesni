CXX=g++
CXX_ARGS=-std=c++20 -Wall -Wextra -maes -msse -msse2 -Ofast
LD=g++
LD_ARGS=
RM=rm
RM_ARGS=-f
ECHO=echo

example : example.cpp.o
	$(LD) $(LD_ARGS) -o example example.cpp.o

example.cpp.o : example.cpp aesni.hpp
	$(CXX) $(CXX_ARGS) -o example.cpp.o -c example.cpp

clean :
	$(RM) $(RM_ARGS) example example.cpp.o
