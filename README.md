# ChainDrop-P2P

# ChainDrop — Secure P2P File Transfer with Blockchain Verification

ChainDrop is a peer-to-peer file transfer system that demonstrates core computer networking concepts through a real-time, multi-client application. Built with Flask and WebSockets, it enables multiple clients to discover each other over a network and exchange files securely, while a lightweight blockchain provides tamper-evident logging of every completed transfer.

## Overview

Each connected client joins a shared network and can transfer files directly to any other peer. Every file is hashed with **SHA-256**, encrypted with **AES-256-GCM**, and streamed to the receiver in **64KB chunks** over a WebSocket connection. All network activity — connection events, transfer progress, and integrity checks — is broadcast live to every connected client, so the system's behavior is fully observable in real time.

On successful transfer, the file's hash is committed to an in-memory blockchain: each block links to the one before it, so any modification to a past record breaks the chain and can be immediately detected. This models how hash-linked ledgers provide data integrity guarantees, without requiring a full distributed consensus implementation.

## Key Concepts Demonstrated

- **Peer-to-peer communication** over WebSockets using Flask-SocketIO
- **Symmetric encryption** (AES-256-GCM) for confidential file transfer
- **Cryptographic hashing** (SHA-256) for file integrity verification
- **Chunked data streaming** for handling files over a network connection
- **Blockchain data structures** for tamper-evident event logging
- **Real-time client synchronization** via server-broadcast events

## Tech Stack

- **Backend:** Python, Flask, Flask-SocketIO
- **Frontend:** HTML, CSS, JavaScript
- **Security:** AES-256-GCM encryption, SHA-256 hashing

## How to Run

1. Extract this folder.
2. Double-click `START.bat` (Windows) — it installs dependencies and starts
   the server, then opens your browser automatically.

   Or manually:
   ```
   pip install flask flask-socketio cryptography
   python app.py
   ```

3. Open **http://localhost:5000** in 5–6 browser tabs.
4. In each tab, type a different username and click "Join Network".

## Project Structure

```
ChainDrop_Clean/
├── app.py              <- Server logic (heavily commented, organized into sections)
├── requirements.txt    <- Python dependencies
├── START.bat           <- One-click launcher for Windows
└── templates/
    └── index.html      <- The webpage / GUI (also heavily commented)
```

## How It Works (Quick Tour)

- **Join Network**: Each browser tab picks a username and "joins" — appears
  in everyone's peer list.
- **Send File**: Select a peer, pick a file. The file is hashed (SHA-256),
  encrypted (AES-256-GCM), split into 64KB chunks, and streamed through the
  server to the receiver.
- **Live Activity Feed** (right sidebar): Everyone sees every event —
  who's sending what to whom, the file's hash, progress, and the final
  verification result. **Only sender and receiver ever see the file content.**
- **Network Check tab**: Shows server status, peer count, and blockchain
  validity — a simple "is everything healthy?" dashboard.
- **Blockchain tab**: Every completed transfer becomes a permanent
  "block" containing the file's hash, linked to the block before it.
- **Private Chat tab**: End-to-end encrypted messages between you and your
  selected peer. Others only see "a message was sent", not its content.

## Where Files Are Saved

When a receiver accepts and the transfer completes, the decrypted file
is automatically downloaded through the browser (to your normal Downloads
folder). The activity feed also shows the recorded save path and the
original sender (file "owner") for that record.

## Notes

- All data (peers, transfers, blockchain) lives in server memory only —
  it resets when you restart `app.py`. This is intentional for a clean demo.
- Designed for up to 6 concurrent users (shown in the Network Check tab).
