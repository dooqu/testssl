#include <cstdlib>
#include <iostream>
#ifdef _WIN32
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <codecvt>
#include "ws_request_parser.h"
#include "ws_request.h"
#include "handshake.h"
#include "ws_framedata_parser.h"
#include "ws_framedata_sender.h"
#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib") 
#endif

typedef unsigned int uint;
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;


class session
{
public:
	session(boost::asio::io_service& io_service,
		boost::asio::ssl::context& context)
		: socket_(io_service, context)
	{
	}

	virtual ~session()
	{
		std::cout << "~session" << std::endl;
	}

	ssl_socket::lowest_layer_type& socket()
	{
		return socket_.lowest_layer();
	}

	void start()
	{
		socket_.async_handshake(boost::asio::ssl::stream_base::server,
			boost::bind(&session::handle_ssl_handshake, this,
				boost::asio::placeholders::error));
	}

	void handle_ssl_handshake(const boost::system::error_code& error)
	{
		if (!error)
		{
			socket_.async_read_some(boost::asio::buffer(data_, max_length),
				boost::bind(&session::handle_ws_handshake_read, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
		else
		{
			delete this;
		}
	}

	void handle_ws_handshake_read(const boost::system::error_code& error, size_t bytes_transferred)
	{
		if (!error)
		{
			std::cout << "HANDSHAKE_RECV:" << data_ << std::endl;
			request_result ret = req_parser_.parse(request_, data_, data_ + bytes_transferred);

			if (ret == ok)
			{
				size_t bytes_readed = 0;
				size_t bytes_to_read = socket_.lowest_layer().available();
				
				if (bytes_to_read > 0)
				{
					std::cout << "bytes_to_read:" << bytes_to_read << std::endl;
					while (bytes_to_read > 0)
					{
						bytes_to_read -= boost::asio::read(socket_, boost::asio::buffer(data_, bytes_to_read));
					}
				}

				bool ret = response_websocket_handshake(request_);

				if (ret)
				{
					return;
				}
			}
			else if (ret == indeterminate)
			{
				socket_.async_read_some(boost::asio::buffer(data_, max_length),
					boost::bind(&session::handle_ws_handshake_read, this,
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred));
				return;
			}
			//请求错误
			delete this;
		}
		else
		{
			delete this;
		}
	}

	void handle_framedata_read(const boost::system::error_code& error, size_t bytes_transferred)
	{
		if (!error)
		{
			do
			{
				framedata_parse_result result = frame_parser_.parse(frame_data_, bytes_transferred);
				if (result == framedata_ok)
				{
					if (frame_data_.opcode_ == 1)
					{
						std::wstring_convert<std::codecvt_utf8<wchar_t>> cvt;
						std::wstring r = cvt.from_bytes(&frame_data_.data[frame_data_.data_pos_], &frame_data_.data[frame_data_.data_pos_ + frame_data_.payload_length_]);
						std::wcout.imbue(std::locale("chs"));
						std::wcout << r << std::endl;
					}
					frame_data_.reset();

					if (frame_data_.pos_ < frame_data_.length)
					{
						//粘包，继续解析
						continue;
					}
					//整包处理完毕，重置，继续读取						
					break;
				}
				else if (result == framedata_indeterminate)
				{
					if (frame_data_.start_pos_ == 0)
					{
						if (bytes_transferred == max_length)
						{
							//溢出，缓冲区装不下一个完整frame数据							
						}						
					}
					else
					{
						//半包数据向前移动
						frame_data_.length = frame_data_.length - frame_data_.start_pos_;						
						memcpy(frame_data_.data, &frame_data_.data[frame_data_.start_pos_], frame_data_.length);
						frame_data_.pos_ = frame_data_.pos_ - frame_data_.start_pos_;						
						frame_data_.data_pos_ = frame_data_.data_pos_ - frame_data_.start_pos_;
						frame_data_.start_pos_ = 0;						
					}
					break;
				}
				else if (result == framedata_error)
				{
					frame_data_.reset();
					break;
				}
				else
				{
					delete this;
					return;
				}

			} while (1);

			socket_.async_read_some(boost::asio::buffer(frame_data_.data, max_length - frame_data_.length),
				boost::bind(&session::handle_framedata_read, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
		else
		{
			delete this;
		}
	}

	bool response_websocket_handshake(ws_request& req)
	{
		int mode = -1;
		bool upgrade = false;
		bool connection = false;
		const char* key = NULL, key1 = NULL, key2 = NULL;

		for (int i = 0, j = req.headers.size(); i < j; i++)
		{
			if (_stricmp(req.headers.at(i).name.c_str(), "Sec-WebSocket-Key") == 0)
			{
				mode = 1;
				key = req.headers.at(i).value.c_str();
				goto _label_mode_1;
			}

			if (upgrade == false && _stricmp(req.headers.at(i).name.c_str(), "Upgrade") == 0 && _stricmp(req.headers.at(i).value.c_str(), "websocket") == 0)
			{
				upgrade = true;
			}

			if (connection == false && _stricmp(req.headers.at(i).name.c_str(), "Connection") == 0 && _stricmp(req.headers.at(i).value.c_str(), "Upgrade") == 0)
			{
				upgrade = true;
			}

			if (connection && upgrade && key != NULL)
			{
				goto _label_mode_1;
			}
		}

	_label_mode_1:
		{
			char key_data[128] = { 0 };
			sprintf(key_data, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);

			char accept_key[29] = { 0 };
			WebSocketHandshake::generate(key, accept_key);

			char buffer[1024] = { 0 };
			int s = sprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept_key);

			boost::asio::async_write(socket_,
				boost::asio::buffer(buffer, s),
				boost::bind(&session::handle_response_handshake, this,
					boost::asio::placeholders::error));
			return true;
		}

		//_label_mode_2:
		//	{
		//		return;
		//	}
		return false;
	}

	void handle_response_handshake(const boost::system::error_code& error)
	{
		if (!error)
		{
			memset(data_, 0, max_length);
			socket_.async_read_some(boost::asio::buffer(frame_data_.data, ws_framedata::max_data_length),
				boost::bind(&session::handle_framedata_read, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
		else
		{
			delete this;
		}
	}

	void handle_write(const boost::system::error_code& error)
	{
		if (!error)
		{
		}
		else
		{
			delete this;
		}
	}

private:
	ssl_socket socket_;
	enum { max_length = 1024 };
	char data_[max_length];
	ws_request request_;
	request_parser req_parser_;
	uint8_t fin_;
	uint8_t opcode_;
	uint8_t mask_;
	uint8_t masking_key_[4];
	uint64_t payload_length_;
	char payload_[1024];
	ws_framedata frame_data_;
	ws_framedata_parser frame_parser_;
	std::string send_buffer;
};

class server
{
public:
	server(boost::asio::io_service& io_service, unsigned short port)
		: io_service_(io_service),
		acceptor_(io_service,
			boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
		context_(boost::asio::ssl::context::sslv23)
	{
		context_.set_options(
			boost::asio::ssl::context::default_workarounds
			| boost::asio::ssl::context::no_sslv2
			| boost::asio::ssl::context::single_dh_use);
		context_.set_password_callback(boost::bind(&server::get_password, this));
		context_.use_certificate_chain_file("server.pem");
		context_.use_private_key_file("server.key", boost::asio::ssl::context::pem);
		//context_.use_tmp_dh_file("dh2048.pem");

		start_accept();
	}

	std::string get_password() const
	{
		return "test";
	}

	void start_accept()
	{
		session* new_session = new session(io_service_, context_);
		acceptor_.async_accept(new_session->socket(),
			boost::bind(&server::handle_accept, this, new_session,
				boost::asio::placeholders::error));
	}

	void handle_accept(session* new_session, const boost::system::error_code& error)
	{
		if (!error)
		{
			std::cout << new_session->socket().remote_endpoint().address().to_string() << std::endl;
			new_session->start();
		}
		else
		{
			delete new_session;
		}

		start_accept();
	}

private:
	boost::asio::io_service& io_service_;
	boost::asio::ip::tcp::acceptor acceptor_;
	boost::asio::ssl::context context_;
};

int main(int argc, char* argv[])
{
	try
	{
		if (argc != 2)
		{
			std::cerr << "Usage: server <port>\n";
			return 1;
		}

		boost::asio::io_service io_service;

		using namespace std; // For atoi.
		server s(io_service, atoi(argv[1]));
		//server s(io_service, 8000);

		io_service.run();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
