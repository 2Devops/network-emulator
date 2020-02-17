#include <dlfcn.h>
#include <stdint.h>
#include <sys/socket.h>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <cstdlib>
#include <iostream>
#include <string>

void x(void)
{

	using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
	namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>
	try
	{
		auto const host = "localhost";
		auto const port = "8888";
		auto const text = "text";

		// The io_context is required for all I/O
		boost::asio::io_context ioc;

		// These objects perform our I/O
		tcp::resolver resolver{ioc};
		websocket::stream<tcp::socket> ws{ioc};

		// Look up the domain name
		auto const results = resolver.resolve(host, port);

		// Make the connection on the IP address we get from a lookup
		boost::asio::connect(ws.next_layer(), results.begin(), results.end());

		// Perform the websocket handshake
		ws.handshake(host, "/");

		// Send the message
		ws.write(boost::asio::buffer(std::string(text)));

		// This buffer will hold the incoming message
		boost::beast::multi_buffer buffer;

		// Read a message into our buffer
		ws.read(buffer);

		// Close the WebSocket connection
		ws.close(websocket::close_code::normal);

		// If we get here then the connection is closed gracefully

		// The buffers() function helps print a ConstBufferSequence
		std::cout << boost::beast::buffers(buffer.data()) << std::endl;
	}
	catch(std::exception const& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}
}
int main(void)
{
    typedef void (*CreateNetAPIOverlay_type)(const uint8_t*, const size_t);
    CreateNetAPIOverlay_type CreateNetAPIOverlay = (CreateNetAPIOverlay_type)dlsym(RTLD_NEXT, "CreateNetAPIOverlay");
    uint8_t data[10240] = {0};
    CreateNetAPIOverlay(data, 10240);

    x();

    typedef void (*DestroyNetAPIOverlay_type)(void);
    DestroyNetAPIOverlay_type DestroyNetAPIOverlay = (DestroyNetAPIOverlay_type)dlsym(RTLD_NEXT, "DestroyNetAPIOverlay");
    DestroyNetAPIOverlay();

    return 0;
}
