# Zynq Updater Client

## Dependencies

1. [Asio](http://think-async.com/) 1.10.6. Header-only networking library.
2. [protobuf](https://github.com/google/protobuf) 3.4.1. Binary serialization library developed by Google.

The headers of both libraries are included as Git submodules under `dependencies/`. You can pull them in by running the following command (assuming Git is installed):

```bash
git submodule update --init
```

### protobuf Library

Even after you pulled in the headers, you need to include the `protobuf` library by:

1. Building `libprotobuf.a` ([instructions](https://github.com/google/protobuf/tree/master/src))
2. Copying the generated static library to `client/libs/`

Regarding (1), use the commands below to cross-compile for 32-bit ARM (i.e., Zynq platform). Note that you **MUST** grab a copy of `protoc` (the protobuf compiler) that runs on the *host* platform before you can cross-compile the library!

``` bash
cd dependencies/protobuf
./configure --host=arm-linux CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ --with-protoc=<PATH_TO_PROTOC>
make
```

Finally, copy the library over to `libs`:

```bash
cd ../../
cp dependencies/protobuf/src/.libs/libprotobuf.a libs/
```

## Build

Navigate to `client/` and run `make` to build the `zynq-updater` binary. If cross compiling, run `make CC=arm-linux-gnueabihf-g++`.
