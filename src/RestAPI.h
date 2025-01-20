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
