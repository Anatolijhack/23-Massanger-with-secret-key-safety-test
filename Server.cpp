#include "Server.h"
#include <iostream>

Server::Server(boost::asio::io_context& io, short port, ThreadPool& pool, Router& router, ChatService& chat)
	: acceptor(io, tcp::endpoint(tcp::v4(), port)),
	pool(pool), router(router),
	chat(chat),
	ssl_context(boost::asio::ssl::context::tlsv12_server)
{
	ssl_context.use_certificate_chain_file("D:/Мои проект/Http Server for Order/x64/Release/server.crt");
	ssl_context.use_private_key_file("D:/Мои проект/Http Server for Order/x64/Release/server.key", boost::asio::ssl::context::pem);

	accept();
}

void Server::accept()
{
	acceptor.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
		if (!ec) {
			std::make_shared<Session>(std::move(socket), pool, router, ssl_context,&chat)->start();
		}
		else {
			std::cerr << "Accept error: " << ec.message() << std::endl;
		}
		accept();
		});
}
