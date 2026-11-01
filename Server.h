#pragma once
#include "Session.h"
#include <boost/asio/ssl.hpp>
#include "Router.h"

class Server
{
private:
	tcp::acceptor acceptor;
	ThreadPool& pool;
	Router& router;
	ChatService& chat;
	boost::asio::ssl::context ssl_context;
public:
	Server(boost::asio::io_context& io, short port, ThreadPool& pool, Router& router, ChatService& chat);
	void accept();
};