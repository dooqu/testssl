#pragma once

#include "ws_framedata_parser.h"
#ifdef _WIN32
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif
#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib") 
#endif

class ws_framedata_sender
{
public:
	static void text_frame(std::string& buffer, char* msg)
	{
		unsigned char fin_byte = 1, paylen_byte = 0;
		fin_byte = fin_byte << 7;
		fin_byte |= 0x1;
		buffer.push_back(fin_byte);

		unsigned long long msg_len = strlen(msg);
		if (msg_len < 126)
		{
			paylen_byte = msg_len;
			buffer.push_back(paylen_byte);
		}
		else if (msg_len < 65535)
		{
			unsigned char byte_len[2] = { 0 };
			unsigned short nlen = htons(msg_len);
			memcpy(byte_len, &nlen, 2);
			buffer.push_back(byte_len[0]);
			buffer.push_back(byte_len[1]);
		}
		else
		{
			unsigned char byte_len[4] = { 0 };
			unsigned long nlen = htonl(msg_len);
			memcpy(byte_len, &nlen, 4);
			buffer.push_back(byte_len[0]);
			buffer.push_back(byte_len[1]);
			buffer.push_back(byte_len[2]);
			buffer.push_back(byte_len[3]);
		}		
		buffer.append(msg);		
	}

	void frame_close(int code, char* reason)
	{
	}

	void response_close_frame(ws_framedata& close_frame)
	{
	}

	void frame_ping()
	{
	}

	void response_ping(ws_framedata& ping_frame)
	{

	}
};