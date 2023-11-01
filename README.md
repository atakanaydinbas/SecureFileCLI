# SecureFileCLI

SecureFileCLI is a command-line tool for secure file encryption and decryption using XOR and AEAD (Authenticated Encryption with Associated Data) algorithms. Protect your sensitive data with a password of your choice.

## Features

- **XOR Algorithm:** Simple yet effective encryption method.
- **AEAD Algorithm:** Provides strong security using the XChaCha20Poly1305 encryption scheme.
- **Command-Line Interface:** Easy-to-use command-line tool for file encryption and decryption.

## Table of Contents

- [Usage](#usage)
- [Installation](#installation)
- [Examples](#examples)
- [Contributing](#contributing)
- [Contact](#contact)

## Usage

```bash
Usage: SecureFileCLI <command> <file_path> <password> <algorithm>
Commands: encrypt, decrypt
Algorithms: xor, aead
```

### XOR Algorithm
Encrypt a File with XOR:

```bash
SecureFileCLI encrypt <file_path> <password> xor
```
Decrypt a File with XOR:

```bash
SecureFileCLI decrypt <file_path> <password> xor
```


### AEAD Algorithm
Encrypt a File with AEAD:

```bash
SecureFileCLI encrypt <file_path> <password> aead
```
Decrypt a File with AEAD:

```bash
SecureFileCLI decrypt <file_path> <password> aead
```
## Installation
Ensure you have Rust and Cargo installed on your system. You can install them from Rust's official website.

Clone the repository:

```bash
git clone https://github.com/atakanaydinbas/SecureFileCLI.git
cd SecureFileCLI
```
Build the project:

```bash
cargo build --release
```
Run the tool:

```bash
cargo run <command> <file_path> <password> <algorithm>
```
## Examples
Here are some example use cases:

Encrypt a File with XOR:

```bash
SecureFileCLI encrypt secret.txt mypassword xor
```
Decrypt a File with AEAD:

```bash
SecureFileCLI decrypt encrypted.aead mypassword aead
```
### Contributing
Contributions to SecureFileCLI are welcome! You can contribute by reporting issues, suggesting new features, or submitting pull requests. Please review our Contribution Guidelines for more information.

### Contact
- Email: atakanaydinbas@gmail.com
