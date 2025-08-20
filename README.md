# SNOW-V Implementation

This repository contains a C++ implementation of the SNOW-V stream cipher with GCM mode for authenticated encryption.

## Overview

SNOW-V is a stream cipher designed for 5G mobile networks, providing high-speed encryption with authenticated encryption capabilities through GCM mode.

## Files

- `SNOWV.h` - Header file containing function declarations
- `SNOWV.cpp` - Main implementation of SNOW-V cipher
- `ghash.h` - Header for GHASH function (GCM mode)
- `testing.cpp` - Test suite with example usage
- `testing.exe` - Compiled test executable

## Building

To compile the project:

```bash
g++ -o testing testing.cpp SNOWV.cpp ghash.cpp
```

## Running Tests

```bash
./testing.exe
```

## Features

- SNOW-V stream cipher implementation
- GCM mode for authenticated encryption
- Encryption and decryption functions
- Test vectors for validation
- Cross-platform C++ code

## Usage

The main functions available are:

- `snowv_gcm_encrypt()` - Encrypt data with authentication
- `snowv_gcm_decrypt()` - Decrypt and verify authenticated data

## License

[Add your license information here]

## Contributing

[Add contribution guidelines if desired]
