#include "SHA.h"
#include <iostream>

int main()
{
	std::string input_string;
	std::getline(std::cin, input_string);
	SHA hasher;
	std::cout << "Hash of " << input_string << ' ' << hasher.hash(input_string) << '\n';
	return 0;
}