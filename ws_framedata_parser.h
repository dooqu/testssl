#ifndef __WS_FRAMEDATA_PARSER__
#define __WS_FRAMEDATA_PARSER__

#include <iostream>
#ifdef _WIN32
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif
#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib") 
#endif

enum framedata_parse_result
{
	framedata_ok,
	framedata_error,
	framedata_indeterminate
};

struct ws_framedata
{
	ws_framedata()
	{
		reset();
	}

	enum state
	{
		ready,
		fin_and_rsv_ok,
		mask_and_payload_len_ok,
		mask_key_ok,
		payload_data_ok
	} state_;

	unsigned char fin_;
	unsigned char rsv1_;
	unsigned char rsv2_;
	unsigned char rsv3_;
	unsigned char opcode_;
	unsigned char mask_;
	unsigned char masking_key_[4];
	unsigned long long payload_length_;
	unsigned int data_pos_;
	unsigned int pos_;
	unsigned int length;
	unsigned int start_pos_;
	unsigned short status;

	enum
	{
		max_data_length = 1024
	};

	char data[max_data_length];

	void reset()
	{
		fin_ = 0;
		rsv1_ = 0;
		rsv2_ = 0;
		rsv3_ = 0;
		opcode_ = 0;
		mask_ = 0;
		payload_length_ = 0;
		data_pos_ = 0;
		pos_ = 0;
		length = 0;
		start_pos_ = 0;
		state_ = ready;
		status = 0;
	}
};

class ws_framedata_parser
{
public:
	framedata_parse_result parse(ws_framedata& frame, size_t data_len)
	{
		//assert(frame.state_ == ws_framedata::ready);
		frame.length += data_len;

		switch (frame.state_)
		{
		case ws_framedata::ready:
			fetch_fin(frame);
			fetch_opcode(frame);
			++frame.pos_;
			frame.state_ = ws_framedata::fin_and_rsv_ok;

		case ws_framedata::fin_and_rsv_ok:
			if (frame.pos_ >= data_len)
				return framedata_indeterminate;
			fetch_mask(frame);

			fetch_payload_length(frame);

			frame.state_ = ws_framedata::mask_and_payload_len_ok;

		case ws_framedata::mask_and_payload_len_ok:
			if (frame.mask_ != 1)
			{
				return framedata_error;
			}
			if (frame.pos_ + 4 > data_len)
			{
				return framedata_indeterminate;
			}
			fetch_masking_key(frame);
			frame.pos_ += 4;
			frame.data_pos_ = frame.pos_;
			frame.state_ = ws_framedata::mask_key_ok;

		case ws_framedata::mask_key_ok:
			if ((frame.pos_ + frame.payload_length_) > data_len)
			{
				return framedata_indeterminate;
			}
			fetch_payload(frame);
			frame.pos_ += frame.payload_length_;
			frame.start_pos_ = frame.pos_;
			frame.state_ = ws_framedata::payload_data_ok;
			return framedata_ok;

		default:
			return framedata_error;
			break;
		}
		return framedata_error;
	}

	int fetch_fin(ws_framedata& frame)
	{
		frame.fin_ = (unsigned char)frame.data[frame.pos_] >> 7;
		frame.rsv1_ = (unsigned char)frame.data[frame.pos_] & 64;
		frame.rsv2_ = (unsigned char)frame.data[frame.pos_] & 32;
		frame.rsv3_ = (unsigned char)frame.data[frame.pos_] & 16;
		std::cout << "fin:" << (frame.fin_ == 1) << std::endl;
		std::cout << "rsv1:" << (frame.rsv1_) << std::endl;
		std::cout << "rsv2:" << (frame.rsv2_) << std::endl;
		std::cout << "rsv3:" << (frame.rsv3_) << std::endl;
		return 0;
	}

	int fetch_opcode(ws_framedata& frame)
	{
		frame.opcode_ = (unsigned char)frame.data[frame.pos_] & 0x0f;
		return 0;
	}

	int fetch_mask(ws_framedata& frame)
	{
		frame.mask_ = (unsigned char)frame.data[frame.pos_] >> 7;
		return 0;
	}

	int fetch_masking_key(ws_framedata& frame)
	{
		for (int i = 0; i < 4; i++)
			frame.masking_key_[i] = frame.data[frame.pos_ + i];

		return 0;
	}

	int fetch_payload_length(ws_framedata& frame)
	{
		frame.payload_length_ = frame.data[frame.pos_] & 0x7f;
		++frame.pos_;

		if (frame.payload_length_ == 126)
		{
			uint16_t length = 0;
			memcpy(&length, frame.data + frame.pos_, 2);
			frame.payload_length_ = ntohs(length);
			frame.pos_ += 2;

			std::cout << "126:payload_length:" << frame.payload_length_ << std::endl;
		}
		else if (frame.payload_length_ == 127)
		{
			uint32_t length = 0;
			memcpy(&length, frame.data + frame.pos_, 4);
			frame.payload_length_ = ntohl(length);
			frame.pos_ += 4;
			std::cout << "127:payload_length:" << frame.payload_length_ << std::endl;
		}

		std::cout << "payload_length: " << frame.payload_length_ << std::endl;
		return 0;
	}

	int fetch_payload(ws_framedata& frame)
	{
		if (frame.mask_)
		{
			for (int i = 0; i < frame.payload_length_; i++)
			{
				int j = i % 4;
				frame.data[frame.pos_ + i] = frame.data[frame.pos_ + i] ^ frame.masking_key_[j];
			}
		}

		if (frame.opcode_ == 8)
		{
			frame.status = 1005;
			//关闭帧的默认status=1005
			if (frame.payload_length_ >= 2)
			{
				//如果是关闭帧，同时在payload数据中填充了关闭原因
				memcpy(&frame.status, frame.data + frame.pos_, 2);
				frame.status = ntohs(frame.status);
				std::cout << "close reason:" << frame.status << std::endl;
			}
		}
		return 0;
	}
};
#endif

