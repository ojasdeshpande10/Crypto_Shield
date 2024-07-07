# CryptoShield

## Overview

CryptoShield is a robust "jump" proxy designed to add an additional layer of encryption and security to publicly accessible TCP services. By acting as an intermediary, Jumproxy decrypts traffic using a symmetric key before relaying it to the intended service. This prevents attackers from exploiting potential zero-day vulnerabilities in the protected service unless they have the secret key.

## Key Features

- **Enhanced Security**: Provides an additional encryption layer using AES-256 in GCM mode.
- **Symmetric Key Encryption**: Uses a static symmetric key derived from a passphrase with PBKDF2.
- **Dual Operation Modes**: Can operate in client-side proxy mode or server-side reverse proxy mode.
- **Concurrency**: Handles multiple concurrent sessions in reverse-proxy mode.
- **Memory-Safe Implementation**: Written in Go, a memory-safe language to avoid memory corruption bugs.

## Usage

### Command Syntax

```bash
go run jumproxy.go [-l listenport] -k pwdfile destination port
