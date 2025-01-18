# Use a base image with C++ and required dependencies
FROM gcc:latest

# Set working directory inside the container
WORKDIR /app

# Install required dependencies (libpcap, etc.)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    cmake \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy the source code into the container
COPY . .

# Ensure the build directory is clean
RUN rm -rf build && mkdir build

# Navigate to the build directory and build the project
WORKDIR /app/build
RUN cmake .. && make

# Debug: Verify the binary exists
RUN ls -l /app/build

# Set the entry point to execute the binary
ENTRYPOINT ["./cloud_native_network_packet_analyzer"]
CMD ["--interface", "en0", "--protocol", "TCP"]