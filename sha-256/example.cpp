#include "sha256.cpp"
#include <iostream>
#include <sstream>
#include <string>

int main(int argc, char** argv)
{
    SHA256 sha256;
    std::stringstream ss;
    ss << argv[1];

    std::cout << "ss.str() = " << ss.str() << std::endl;

    std::cout << "SHA256: " << sha256.hash(ss.str()) << std::endl;
}