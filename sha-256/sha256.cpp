#include "sha256.h"
#include <stdio.h>
#include <string>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <sstream>
#include <cstdint>

using uint32 = uint32_t;

std::string SHA256::hash(std::string input)
{
	size_t nBuffer;
	uint32** buffer;
	uint32* h = new uint32[HASH_LEN];

	buffer = preprocess((unsigned char*) input.c_str(), nBuffer);
	process(buffer, nBuffer, h);

	for(size_t i=0; i<nBuffer; i++)
		delete[] buffer[i];

	delete[] buffer;
	return digest(h);
}

uint32** SHA256::preprocess(const unsigned char* input, size_t &nBuffer)
{
	size_t mLen = strlen((const char*) input);
	size_t l = mLen * CHAR_LEN_BITS;
	size_t k = (448 - 1 - l) % MESSAGE_BLOCK_SIZE;
	nBuffer = (l + 1 + k + 64) / MESSAGE_BLOCK_SIZE;

	uint32** buffer = new uint32*[nBuffer];

	for(size_t i = 0; i < nBuffer; i++)
		buffer[i] = new uint32[SEQUENCE_LEN];

	uint32 in;
	size_t index;

	for(size_t i = 0; i < nBuffer; i++)
    {
		for(size_t j = 0; j < SEQUENCE_LEN; j++)
        {
			in = static_cast<unsigned int>(0x00u);
			for(size_t k = 0; k < WORD_LEN; k++)
            {
				index = i * 64 + j * 4 + k;
				if(index < mLen)
					in = in << 8 | static_cast<unsigned int>(input[index]);
                else if(index == mLen)
					in = in << 8 | static_cast<unsigned int>(0x80u);
                else
					in = in << 8 | static_cast<unsigned int>(0x00u);
			}
			buffer[i][j] = in;
		}
	}

	appendLen(l, buffer[nBuffer-1][SEQUENCE_LEN-1], buffer[nBuffer-1][SEQUENCE_LEN-2]);
	return buffer;
}


void SHA256::process(uint32** buffer, size_t nBuffer, uint32* h)
{
	uint32 s[WORKING_VAR_LEN];
	uint32 w[MESSAGE_SCHEDULE_LEN]; 

	memcpy(h, hPrime, WORKING_VAR_LEN*sizeof(uint32));

	for(size_t i=0; i<nBuffer; i++)
    {
		memcpy(w, buffer[i], SEQUENCE_LEN*sizeof(uint32));

		for(size_t j = 16; j < MESSAGE_SCHEDULE_LEN; j++)
			w[j] = w[j - 16] + sig0_s(w[j - 15]) + w[j - 7] + sig1_s(w[j - 2]);
		
		memcpy(s, h, WORKING_VAR_LEN*sizeof(uint32));

		for(size_t j = 0; j < MESSAGE_SCHEDULE_LEN; j++)
        {
			uint32 temp1 = s[7] + Sig1_s(s[4]) + Ch_s(s[4], s[5], s[6]) + k[j] + w[j];
			uint32 temp2 = Sig0_s(s[0]) + Maj_s(s[0], s[1], s[2]);

            for(size_t i = 7;i > 0;i--)
            {
                if(i != 4 && i != 0)
                    s[i] = s[i - 1];
                else if(i == 4)
                    s[i] = s[i - 1] + temp1;
                else if(i == 0)
                    s[i] = temp1 + temp2;

            }
		}

		for(size_t j = 0; j < WORKING_VAR_LEN; j++)
			h[j] += s[j];
	}

}

void SHA256::appendLen(size_t l, uint32& lo, uint32& hi)
{
	lo = l;
	hi = 0x00;
}

std::string SHA256::digest(uint32* h)
{
	std::stringstream ss;
	for(size_t i = 0; i < OUTPUT_LEN; i++)
		ss << std::hex << std::setw(8) << std::setfill('0') << h[i];

	delete[] h;
	return ss.str();
}