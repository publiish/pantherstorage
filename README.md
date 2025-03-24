## Private IPFS-Cluster API Setup

This repository provides configuration to deploy a private IPFS network with clustered nodes and gateways. Whether you're setting up your first node or expanding an existing network, this walkthrough will guide the process step by step.

### Overview

### A. Endpoints Workflow
All endpoints are prefixed with `/api`. If the server is running at `http://localhost:8081`, the full URL for the `/signup` endpoint would be `http://localhost:8081/api/signup`.

### B. First IPFS Node & Cluster Node
Establish the foundation of your private IPFS cluster.

### C. Additional IPFS & Cluster Nodes
Scale your network by adding new members.

### D. Cluster Gateway API
Enable cluster services like pinning and management.

### E. IPFS Gateway
Provide public file access via an IPFS gateway.

**Key Insight:** The setup process is consistent across all nodes. The main difference lies in the use of secret keys and bootstrap nodes:

- **First Node:** Generates new swarm and cluster keys; no bootstrap nodes required.
- **Subsequent Nodes:** Reuse existing keys and connect to the first node as the bootstrap.

### SWARM_KEY - How to Generate?
The `SWARM_KEY` is a private key used by IPFS to create a private network, ensuring that only nodes with the same key can connect to each other. It restricts the IPFS swarm to a specific set of peers, isolating it from the public IPFS network.

The SWARM_KEY is a 32-byte (64-character hexadecimal) key prefixed with a specific header. Here’s how to generate it: 

**On Linux/macOS (using /dev/urandom)**

```bash
echo $(od -vN 32 -An -tx1 /dev/urandom | tr -d ' \n')
```

```
echo "/key/swarm/psk/1.0.0/" > swarm.key
echo "/base16/" >> swarm.key
tr -dc 'a-f0-9' < /dev/urandom | head -c64 >> swarm.key
```

**On Windows (using PowerShell)**
```
$key = -join ((0..9) + ('a'..'f') | Get-Random -Count 64)
"/key/swarm/psk/1.0.0/`n/base16/`n$key" | Out-File -FilePath swarm.key
```

### Prerequisites

- **Operating System:** Ubuntu (or any Debian-based Linux OS).
- **Docker:** Install with docker-compose for container management.
- **User Permissions:** Ensure your user has Docker access.

### Basic Installation for Different Operating System

### 1. Linux (Ubuntu/Debian)

#### Install Docker and Docker Compose:

```bash
sudo apt update
sudo apt install docker.io
sudo apt install -y docker-compose
```

#### Add Your User to the Docker Group:

```bash
sudo usermod -a -G docker $USER
```

#### Apply Changes:
Restart your terminal or log out and back in to refresh group permissions.

### 2. macOS - Ensure the user has appropriate permissions to run Docker commands

#### Install Docker and Docker Compose:

```bash
brew install docker docker-compose
```

### 3. Windows - Install Docker Desktop from the official site and enable WSL2

### Configuration

### IPFS Node: Swarm Key
The swarm key ensures your IPFS nodes operate in a private network.

Add this to `docker-compose.yml` under the `SWARM_KEY` environment variable.

### IPFS Cluster Node: Cluster Secret
The cluster secret is a 32-byte (64-character hexadecimal) key used by IPFS-Cluster to secure communication between cluster peers. It ensures that only nodes with the same secret can participate in the cluster, providing authentication and encryption for cluster operations like pinning and replication.

#### For the First Node:
Generate a new cluster secret (another 32-byte hex string):

```bash
echo -e "`tr -dc 'a-f0-9' < /dev/urandom | head -c64`"
```
**Sample Output:**

```
c2fa323fd396ac146abac7c7b9a99d2ca4a035644ab5207ed22570ff5bf8aa7
```

Add this to `docker-compose.yml` under the `CLUSTER_SECRET` environment variable.

#### For Additional Nodes:
Obtain the existing swarm key from the network admin and reuse it in `docker-compose.yml`.

### Running the Setup
Build and Start the Services:

```bash
docker-compose up -d --build
```

This command builds the IPFS and IPFS Cluster images and starts all services (IPFS node, cluster node, cluster gateway, and IPFS gateway) in the background.

Configuration files are persisted in:
- **IPFS:** `/home/$USER/.compose/ipfs`
- **Cluster:** `/home/$USER/.compose/cluster`

### Stopping the Services:

```bash
docker-compose down
```

### Restarting the Services:
After the initial build, use:

```bash
docker-compose up -d
```

### Check Cluster Status
Verify that your cluster nodes are connected:

```bash
docker container exec cluster0 ipfs-cluster-ctl peers ls
```

This lists all peers in the cluster. For a multi node setup, ensure all expected peers appear within a few seconds.

### Exposed Ports
- **IPFS Swarm:** 4001 (optional exposure for external connections).
- **IPFS API:** 5001 (optional exposure).
- **IPFS Gateway:** 8080 (public file access).
- **Cluster API:** 9094 (for `ipfs-cluster-ctl` commands).

### Adding New Nodes
1. Copy the `docker-compose.yml` file to the new machine.
2. Update the `CLUSTER_IPFSHTTP_NODEMULTIADDRESS` to point to the new IPFS node (e.g., `/dns4/ipfs1/tcp/5001`).
3. Use the same `SWARM_KEY` and `CLUSTER_SECRET` from the first node.
4. Set the first node as the bootstrap node (edit IPFS and cluster configs if needed).
5. Run:

```bash
docker-compose up -d --build
```

## Actix Web API with IPFS Integration

This is an Actix Web-based API that integrates with an IPFS service for file storage and retrieval. The application includes middleware, rate limiting, logging, and configuration management.

### Prerequisites

Ensure you have the following installed:
- [Rust](https://www.rust-lang.org/) (latest stable version)
- [Cargo](https://doc.rust-lang.org/cargo/) (comes with Rust)
- [IPFS Daemon](https://docs.ipfs.tech/) (if interacting with a local IPFS node and not using docker-compose file services, install IPFS manually or via a package manager like `brew` on macOS, `apt` on Ubuntu, or `choco` on Windows)

### Installation

Clone the repository:
```sh
git clone https://github.com/surajk-m/publiish-api
cd publiish-api
```

Install Rust if not already installed:
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Rustc compiled version
```
rustc 1.84.1 (e71f9a9a9 2025-01-27)
```

Verify installation:
```sh
rustc --version
cargo --version
```

### Running the Application

Set up environment variables (example in `.env` file):
```sh
DATABASE_URL=mysql://root:password@localhost:3306/publiish_local
IPFS_NODE=http://127.0.0.1:5001
BIND_ADDRESS=127.0.0.1:8081
MAX_CONCURRENT_UPLOADS=42
RUST_LOG=info
```

Run the application:
```sh
cargo run
```

### Building and Running in Production

To build the application for production:
```sh
cargo build --release
```

Run the built binary:
```sh
./target/release/publiish-api
```

Generate the `Dilithium keys` and update `.env` file with `DILITHIUM_PUBLIC_KEY` and `DILITHIUM_PRIVATE_KEY`:
```sh
cargo run -- generate-keys --base64
```

## API Documentation

This document provides an overview of the available API endpoints, their expected request formats, and example curl commands for testing.

### Endpoints Workflow

- **POST** `/api/signup` - Register a new user
- **POST** `/api/signin` - Authenticate a user and get a PQS token
- **POST** `/api/upload` - Upload a file (requires authentication)
- **POST** `/api/delete` - Unpin a file (requires authentication)
- **GET** `/api/pins` - List pinned files (requires authentication)
- **GET** `/api/download/{cid}` - Download a file (requires authentication)
- **GET** `/api/metadata/{cid}` - Get file metadata (requires authentication)
- **GET** `/api/upload/status/{task_id}` - Get upload task status (requires authentication)

### API Usage Examples

### 1. Signup

- **Description:** Registers a new user and returns a PQS token.
- **Method:** POST
- **Endpoint:** `/api/signup`
- **Request Body:**

  ```json
  {
    "username": "testuser",
    "email": "test@example.com",
    "password": "Passw0rd!"
  }
  ```

- **Response:**

  ```json
  {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.."
  }
  ```
  
- **Curl Command:**

  ```bash
  curl -X POST http://0.0.0.0:8081/api/signup \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "Passw0rd!"}'
  ```

### 2. Signin

- **Description:** Authenticates a user and returns a PQS token.
- **Method:** POST
- **Endpoint:** `/api/signin`
- **Request Body:**

  ```json
  {
    "email": "test@example.com",
    "password": "Passw0rd!"
  }
  ```

- **Response:**

  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ..."
  }
  ```

- **Curl Command:**

  ```bash
  curl -X POST http://0.0.0.0:8081/api/signin \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "Passw0rd!"}'
  ```

### 3. Upload File

- **Description:** Uploads a file and stores its metadata. Supports synchronous and asynchronous modes.
- **Method:** POST
- **Endpoint:** `/api/upload`
- **Query Parameter**: async=true (optional, for asynchronous upload)
- **Request Body:** Multipart form data with a file field containing the file content.

- **Response(Synchronous):**

  ```json
  {
    "cid": "QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o",
    "name": "example.txt",
    "size": 42,
    "timestamp": "2025-03-17 07:23:27.320688272 UTC",
    "user_id": 1
  }
  ```

- **Response(Asynchronous):**

  ```json
  {
    "task_id": "c21fc79c-44e4-4d87-9321-1adf6a4fc1df",
    "status": "pending",
    "cid": null,
    "error": null,
    "progress": 0.0,
    "started_at": "2025-03-21 10:00:00.123456 UTC"
  }
  ```

- **Curl Command (Synchronous):**

  ```bash
  curl -X POST http://0.0.0.0:8081/api/upload \
  -H "Content-Type: multipart/form-data" \
  -H "Authorization: Bearer <PQS_TOKEN>" \
  -F "file=@/path/to/example.txt"
  ```

- **Curl Command (Asynchronous):**

  ```bash
  curl -X POST http://0.0.0.0:8081/api/upload?async=true \
  -H "Authorization: Bearer <PQS_TOKEN>" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/example.txt"
  ```

### 4. Download File

- **Description:** Downloads a file buffer stream from IPFS.
- **Method:** GET
- **Endpoint:** `/api/download/{cid}`
- **Request Headers:** Authorization: Bearer <PQS_TOKEN>
- **Response:** File fetched by user. Binary file content with appropriate `Content-Type` and `Content-Disposition` headers.
- **Notes:** The `Content-Type` is inferred from the file extension, defaulting to `application/octet-stream`.

- **Curl Command:**

  ```bash
  curl -X GET http://localhost:8081/api/download/QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o \
  -H "Authorization: Bearer <PQS_TOKEN>" \
  -o testfile
  ```

### 5. Delete File

- **Description:** Deletes a file from IPFS and removes its metadata.
- **Method:** POST
- **Endpoint:** `/api/delete`
- **Request Body:**

  ```json
  {
    "cid": "Qm..."
  }
  ```

- **Response:** File deleted successfully.

- **Curl Command:**

  ```bash
  curl -X POST http://0.0.0.0:8081/api/delete \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <PQS_TOKEN>" \
  -d '{"cid": "QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o"}'
  ```

### 6. List Pins

- **Description:** Lists all pinned files for the authenticated user.
- **Method:** GET
- **Endpoint:** `/api/pins`
- **Response:**

  ```json
  ["QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o", "Qm..."]
  ```

- **Curl Command:**

  ```bash
  curl -X GET http://0.0.0.0:8081/api/pins \
  -H "Authorization: Bearer <PQS_TOKEN>"
  ```

### 7. Get File Metadata

- **Description:** Retrieves metadata for a specific file.
- **Method:** GET
- **Endpoint:** `/api/metadata/{cid}`
- **Response:**

  ```json
  {
    "cid": "Qm...",
    "name": "file.txt",
    "size": 12,
    "timestamp": "2025-03-14 23:57:13.657188060 UTC",
    "user_id": 1
  }
  ```

- **Curl Command:**

  ```bash
  curl -X GET http://0.0.0.0:8081/api/metadata/QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o \
  -H "Authorization: Bearer <PQS_TOKEN>"
  ```

### 8. Get Upload Status

- **Description:** Retrieves the status of an asynchronous upload task.
- **Method:** GET
- **Endpoint:** `/api/upload/status/{task_id}`
- **Response:**

  ```json
  {
    "task_id": "c21fc79c-44e4-4d87-9321-1adf6a4fc1df",
    "status": "completed",
    "cid": "QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o",
    "error": null,
    "progress": 100.0,
    "started_at": "2025-03-21 10:00:00.123456 UTC"
  }
  ```

- **Curl Command:**

  ```bash
  curl -X GET http://0.0.0.0:8081/api/upload/status/c21fc79c-44e4-4d87-9321-1adf6a4fc1df \
  -H "Authorization: Bearer <PQS_TOKEN>"
  ```