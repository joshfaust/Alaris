#pragma once

#include <string>
#include <iostream>
#include <Windows.h>
#include <string>
#include <stdio.h>

class base64
{
public:

	std::string base64_encode(unsigned char const*, unsigned int len);
	std::string base64_decode(std::string const& s);


};

