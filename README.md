## Zynq Updater

This is the repo for the Zynq updater software.

There are two main components:

1. A client, written in C++11
2. A server, written for Python 3.5

### Client

Before you can build the client app, you will need to do the following:

1. Grab the [`src/` directory](https://github.com/google/protobuf/tree/master/src) of `protobuf` and copy it to `client/dependencies/protobuf`.
2. Build `libprotobuf` ([instructions](https://github.com/google/protobuf/tree/master/src)) and copy the generated static library (.a) to `client/libs`.
3. Grab the [include directory](https://github.com/chriskohlhoff/asio/tree/master/asio/include) of `asio` and copy it to `client/dependencies/asio`.

Once this is done, navigate to `client/` and run `make` to build the client binary. If cross compiling, run `CC=arm-linux-gnueabihf-g++ make` instead.

### Server

Install the `protobuf` Python package. The easiest way to do this on any platform is through Anaconda: `conda install protobuf`.
