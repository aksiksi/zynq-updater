# Zynq Updater Client

## Dependencies

1. [Asio](http://think-async.com/) 1.10.6. Header-only networking library. Included under `dependencies/`.
2. [protobuf](https://github.com/google/protobuf) 3.4.1. Binary serialization library developed by Google.  

## Pre-build

Before you can build the client app, you will need to include `protobuf` in the project as follows:

1. Grab the `src/` directory from the `protobuf` [Github repo](https://github.com/google/protobuf/tree/master/src) and copy it to `client/dependencies/protobuf/`.
2. Build `libprotobuf` ([instructions](https://github.com/google/protobuf/tree/master/src)) and copy the generated static library (.a) to `client/libs/`.

## Build

Navigate to `client/` and run `make` to build the `zynq-updater` binary. 

If cross compiling, run `CC=arm-linux-gnueabihf-g++ make` instead.
