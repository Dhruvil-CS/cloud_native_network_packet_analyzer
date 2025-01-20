# Cloud Native Network Packet Analyzer

This project is a **Cloud Native Network Packet Analyzer** that captures and analyzes network packets in real-time.
It provides an HTTP API to fetch captured packet data and displays it on a simple web dashboard.
The application uses C++ with libraries like `Boost.Asio`, `Boost.Beast`, and `libpcap` for packet capture and HTTP server functionality.

The system consists of multiple components:

1. **Packet Sniffer**: Captures network packets based on a protocol filter (TCP, UDP, or ICMP) from a specified interface.
2. **REST API**: Exposes a simple HTTP server to fetch captured packet data in JSON format.
3. **Web Interface**: A dashboard to display the captured packets on a web page.

## Features

- Captures network packets using the `libpcap` library.
- Filters packets based on specified protocols (TCP, UDP, ICMP).
- Provides a REST API for retrieving captured packets in JSON format.
- Simple web interface to view the captured packets.
- Displays statistics about captured packets such as total packets, TCP packets, UDP packets, ICMP packets, and total bytes.
- Configurable packet capture interface and protocol through command-line arguments.

## Getting Started

### Prerequisites

- **C++ Compiler** (GCC or Clang)
- **CMake** for building the project
- **libpcap** for packet capturing
- **Boost Libraries** (Asio and Beast)

### Installation

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/yourusername/cloud-native-network-packet-analyzer.git
    cd cloud-native-network-packet-analyzer
    ```

2. Build the project using CMake:

    ```bash
    mkdir build
    cd build
    cmake ..
    make
    ```

3. Run the program with the appropriate interface and protocol:

    ```bash
    sudo ./cloud_native_network_packet_analyzer --interface <interface> --protocol <protocol>
    ```

    Example:

    ```bash
    sudo ./cloud_native_network_packet_analyzer --interface en0 --protocol TCP
    ```

## Web Interface

The `index.html` file provides a simple dashboard to view the captured packets.
It refreshes the data automatically or can be manually refreshed by clicking the "Refresh" button.

## Accessing the REST API

The REST API is exposed at `http://localhost:5050/packets`.
It returns a JSON response with the captured packets in the following format:

    ```
    {
        "packets": [
            "Captured packet of length 100",
            "Captured packet of length 200"
        ]
    }
    ```

## Project Structure

- `RestAPI.h` / `RestAPI.cpp`: Defines the REST API server, handling HTTP requests and responding with captured packet data.
- `PacketSniffer.h` / `PacketSniffer.cpp`: Defines the packet sniffer class, responsible for capturing network packets and processing them.
- `main.cpp`: The entry point for the application, initializing the packet sniffer and the REST API server.
- `index.html`: Web interface for displaying captured packets.
- `Dockerfile`: Docker configuration for building and running the application in a container.

