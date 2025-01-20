/*The RestAPI.h file is the header file for the RestAPI class in a C++ project. 
It defines the structure and interface of the RestAPI class, which is responsible for managing an HTTP server that- 
exposes network packet data collected by a packet analyzer application. 
This file serves as a blueprint for implementing the REST API server.
*/
#ifndef REST_API_H
#define REST_API_H

#include <boost/asio.hpp>
#include <boost/beast.hpp>

class RestAPI {
public:
    RestAPI();
    void startServer(int port);
private:
    void handleRequest(boost::beast::http::request<boost::beast::http::string_body>& req);
};

#endif
