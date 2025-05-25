# TURN Server

A Rust-based TURN (Traversal Using Relays around NAT) server implementation that uses a SansIO architecture for better separation of concerns and testability.

## Overview

This project implements a TURN server using the `turn-service` crate, which follows the SansIO (Sans Input/Output) design pattern. The SansIO pattern separates the core protocol logic from the I/O operations, making the code more modular, testable, and maintainable.

## Features

- UDP and TCP support for TURN protocol
- OpenTelemetry integration for tracing and metrics
- Configurable server settings
- Custom authentication support
- SansIO architecture for clean separation of concerns

## Architecture

The project uses a SansIO architecture, which means:

1. The core TURN protocol logic is completely separated from I/O operations
2. Protocol state machines are pure and don't depend on I/O
3. I/O operations are handled by separate layers
4. Better testability as protocol logic can be tested without I/O dependencies

## Dependencies

- `turn-service`: Core TURN protocol implementation
- `tokio`: Async runtime
- `opentelemetry`: Distributed tracing and metrics
- `anyhow`: Error handling
- `tracing`: Logging and instrumentation

## Configuration

The server can be configured through the `InstanceConfig` struct. Current configuration options include:

- Server address
- UDP ports
- TCP ports

## Usage

1. Build the project:
```bash
cargo build
```

2. Run the server:
```bash
just run
```

The server will start listening on the configured ports (default: 3478) for both UDP and TCP connections.

## Authentication

The server implements a simple username/password authentication system. Currently, it supports the following test credentials:

- Username: "dinesh", Password: "test"
- Username: "boose", Password: "dumeel"

## Monitoring

The server integrates with OpenTelemetry for:

- Distributed tracing
- Metrics collection
- Performance monitoring
