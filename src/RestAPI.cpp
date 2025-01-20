#include "RestAPI.h"
#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include "PacketSniffer.h"

using json = nlohmann::json;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
RestAPI::RestAPI() {
    // Constructor code (if any initialization is needed)
    // In this case, the constructor doesn't need to perform any actions, but you can add logic if necessary.
}
void RestAPI::startServer(int port) {
    try {
        net::io_context ioc;
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), port));
        std::cout << "Server started on port " << port << std::endl;

        for (;;) {
            tcp::socket socket(ioc);
            acceptor.accept(socket);

            http::request<http::string_body> req;
            beast::flat_buffer buffer;
            http::read(socket, buffer, req);

            json responseJson;
            if (req.method() == http::verb::get && req.target() == "/packets") {
                responseJson["packets"] = PacketSniffer::getCapturedPackets();
            } else {
                responseJson["error"] = "Invalid endpoint";
            }

            http::response<http::string_body> res{http::status::ok, req.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = responseJson.dump();
            res.prepare_payload();
            http::write(socket, res);
        }
    } catch (std::exception& e) {
        std::cerr << "Error in REST API: " << e.what() << std::endl;
    }
}
