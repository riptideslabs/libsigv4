# AWS SigV4 C Library

[![Build](https://github.com/riptideslabs/libsigv4/actions/workflows/build.yml/badge.svg)](https://github.com/riptideslabs/libsigv4/actions/workflows/build.yml)

This project provides a C implementation of AWS Signature Version 4 (SigV4) signing, suitable for use in embedded, kernel, or user-space applications. It includes a shared library and an example application demonstrating usage.

## Features
- AWS SigV4 signing for HTTP requests
- No dynamic memory allocations
- Pluggable cryptographic backend integration (not limited to OpenSSL)
- Simple API for integration into C projects
- Supports signing additional headers 
- Example usage and tests included
- System header configurability via `SIGV4_SYSTEM_HEADER`

## Building

### Prerequisites
- GCC or compatible C compiler
- `pkg-config` utility
- [OpenSSL](https://github.com/openssl/openssl) for testing, and examples
- [libcheck](https://github.com/libcheck/check) for testing

### Build Instructions

```sh
sudo apt install libssl-dev check
```

To build the shared library and example application, run:

```sh
make
```

This will produce:
- `libsigv4.so`: Shared library implementing SigV4
- `example`: Example application using the library

### Clean Build Artifacts

```sh
make clean
```

## Usage

### System Header Configurability
You can configure the system header used by the library by defining the macro `SIGV4_SYSTEM_HEADER` during compilation. This allows integration with custom or platform-specific headers as needed.

Example:
```sh
gcc -DSIGV4_SYSTEM_HEADER='<your_header.h>' ...
```

### Linking
Include the header in your application:

```c
#include "sigv4.h"
```

Link against the shared library and your selected crypto backend:

```
-L. -lsigv4 [crypto backend linkage]
```

### Example
See `example.c` for a usage demonstration.

## License
See `LICENSE` for details.

## Contributing
Pull requests and issues are welcome!

## Acknowledgments

Special thanks to Shi Bai, who created the original version of this library: https://github.com/sidbai/aws-sigv4-c
