# Stage 1: Build the Rust application
FROM rust:latest AS builder

# Set the working directory
WORKDIR /app

# Copy the Cargo manifest files to cache dependencies
COPY publiish-api/Cargo.toml publiish-api/Cargo.lock ./

# Create a dummy source file to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Fetch and compile dependencies
RUN cargo build --release

# Copy the actual source code from the publiish-api folder
COPY publiish-api/src ./src

# Rebuild the application with the actual source code
RUN cargo build --release

# Stage 2: Create the final runtime image
FROM debian:bookworm-slim

# Set the working directory
WORKDIR /app

# Install necessary runtime dependencies
RUN apt-get update && apt-get install -y \
    curl dnsutils libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/publiish-api /app/publiish-api

# Ensure the binary has execution permissions
RUN chmod +x /app/publiish-api

# Expose the required port
EXPOSE 8081

# Run the application
CMD ["/app/publiish-api"]