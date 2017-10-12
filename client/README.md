# Zynq Updater Client

To build this client, you must have a cross-compiler toolchain for the 32-bit ARM platform. On Ubuntu, simply run:

```bash
sudo apt-get install gcc-arm-linux-gnueabihf
```

If you have PetaLinux installed, you can just source in the PetaLinux settings script:

```bash
source <PETALINUX_INSTALL_DIR>/settings.sh
```

## Dependencies

1. [Asio](http://think-async.com/) 1.10.6. Header-only networking library.
2. [protobuf](https://github.com/google/protobuf) 3.4.1. Binary serialization library developed by Google.

The headers of both libraries are included as Git submodules under `dependencies/`. 

Pull them in by running the following command (assuming Git is installed):

```bash
git submodule update --init
```

### protobuf Library

You need to include the `protobuf` shared library by:

1. Building `libprotobuf.a` ([instructions](https://github.com/google/protobuf/tree/master/src))
2. Copying the generated static library to `client/libs/`

Use the commands below to cross-compile `protobuf` for 32-bit ARM (i.e., the Zynq platform). You **MUST** obtain a copy of `protoc` (the protobuf compiler) that runs on the *host* platform before you can cross-compile the library! The Github releases page includes pre-compiled binaries for Linux, OS X, and Windows.

Configure and build the shared library;

``` bash
cd dependencies/protobuf
./configure --host=arm-linux CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ --with-protoc=<PATH_TO_PROTOC>
make
```

Copy the library over to `libs`:

```bash
cd ../../
cp dependencies/protobuf/src/.libs/libprotobuf.a libs/
```

## Build

Navigate to `client/` and run `make` to build the `zynq-updater` binary.
