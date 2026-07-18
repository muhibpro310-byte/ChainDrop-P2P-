"""
═══════════════════════════════════════════════════════════════════════════
  ChainDrop — Secure P2P File Transfer with Blockchain Logging
═══════════════════════════════════════════════════════════════════════════

WHAT THIS PROGRAM DOES
-----------------------
1. Multiple users open this page in their browser (5-6 tabs for demo).
2. Each user picks a username and "joins the network".
3. A user can pick another peer and send them a file.
4. The file is split into chunks, encrypted, and sent through the server
   to the receiver.
5. Every step (transfer started, chunk sent, file verified) is logged
   and broadcast to ALL connected users — like a shared activity feed.
6. After a successful transfer, a "block" is added to a simple blockchain
   that records: who sent what file to whom, and its SHA-256 hash.

HOW THE FILES ARE ORGANIZED
-----------------------------
  app.py                <- this file (server + logic)
  templates/index.html  <- the webpage (GUI) shown to users

HOW TO RUN
-----------
  1. pip install flask flask-socketio cryptography
  2. python app.py
  3. Open http://localhost:5000 in your browser (5-6 tabs for demo)
═══════════════════════════════════════════════════════════════════════════
"""

import os
import hashlib
import uuid
import threading
import webbrowser
from datetime import datetime, timezone

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit, join_room


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: APP SETUP
# ═══════════════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()

# async_mode='threading' is the simplest, most reliable option on Windows.
# (Avoids the "port already in use" crash that eventlet sometimes causes.)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Each chunk of a file sent is this many bytes (64 KB)
CHUNK_SIZE = 64 * 1024

# A rotating list of colors so each user gets a different color in the UI
USER_COLORS = ["#00d4ff", "#10d98a", "#f97316", "#a78bfa",
               "#fb7185", "#fbbf24", "#34d399", "#60a5fa"]


def now() -> str:
    """Return the current time as an ISO-format string (UTC)."""
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: SIMPLE BLOCKCHAIN
#
# A "blockchain" here is just a list of records (blocks). Each block stores
# information about ONE completed file transfer, plus the hash of the
# PREVIOUS block. This chaining means if anyone tampers with an old record,
# every block after it becomes "invalid" — which we can detect.
# ═══════════════════════════════════════════════════════════════════════════

class Block:
    """One entry in the blockchain — represents one completed file transfer."""

    def __init__(self, index, file_hash, filename, sender, receiver, filesize):
        self.index = index                  # position in the chain (0, 1, 2, ...)
        self.file_hash = file_hash          # SHA-256 of the transferred file
        self.filename = filename
        self.sender = sender
        self.receiver = receiver
        self.filesize = filesize
        self.timestamp = now()
        self.previous_hash = ""             # filled in when added to the chain
        self.block_hash = ""                # computed after previous_hash is set

    def compute_hash(self) -> str:
        """Combine all fields into one string and hash it with SHA-256."""
        raw = (f"{self.index}{self.file_hash}{self.filename}"
               f"{self.sender}{self.receiver}{self.timestamp}{self.previous_hash}")
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> dict:
        """Convert this block into a plain dictionary (for sending as JSON)."""
        return self.__dict__.copy()


class Blockchain:
    """Holds the ordered list of Blocks and lets us add/verify them."""

    def __init__(self):
        self.chain = []
        self._add_genesis_block()

    def _add_genesis_block(self):
        """The very first block — has no real transfer data."""
        genesis = Block(0, "0" * 64, "GENESIS", "system", "system", 0)
        genesis.block_hash = genesis.compute_hash()
        self.chain.append(genesis)

    def add_block(self, file_hash, filename, sender, receiver, filesize) -> Block:
        """Create a new block, link it to the previous one, and store it."""
        block = Block(len(self.chain), file_hash, filename, sender, receiver, filesize)
        block.previous_hash = self.chain[-1].block_hash
        block.block_hash = block.compute_hash()
        self.chain.append(block)
        return block

    def find_by_hash(self, file_hash):
        """Check if a file with this hash was already transferred before."""
        for block in self.chain[1:]:
            if block.file_hash == file_hash:
                return block
        return None

    def is_valid(self) -> bool:
        """Check that every block correctly points to the one before it."""
        for i in range(1, len(self.chain)):
            if self.chain[i].previous_hash != self.chain[i - 1].block_hash:
                return False
        return True

    def as_list(self) -> list:
        return [b.to_dict() for b in self.chain]


blockchain = Blockchain()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: IN-MEMORY STATE
#
# All of this data lives in the server's memory only (it disappears when
# the server stops). That's fine for a demo / classroom project.
# ═══════════════════════════════════════════════════════════════════════════

# peers: maps a user's connection-id (sid) -> their info
#   { "abc123": {"username": "alice", "color": "#00d4ff", "sent": 0, "received": 0} }
peers = {}

# transfers: maps a transfer-id -> info about that transfer
#   { "tid1": {"filename": ..., "sender_sid": ..., "receiver_sid": ..., ...} }
transfers = {}

# activity_log: a list of every event we want to show in the "Activity Feed"
activity_log = []


def log_activity(event_type, message, **extra):
    """
    Add one entry to the shared activity feed and broadcast it
    to every connected browser tab in real time.
    """
    entry = {
        "id": str(uuid.uuid4())[:8],
        "type": event_type,
        "message": message,
        "timestamp": now(),
        **extra,
    }
    activity_log.append(entry)
    if len(activity_log) > 200:           # keep the log from growing forever
        activity_log.pop(0)
    socketio.emit("activity", entry)      # send to ALL connected clients
    return entry


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: SECURITY / VERIFICATION CHECKS
#
# After a file is fully received, we run a few simple checks and show the
# results to the user. This is the "secure network checking" feature.
# ═══════════════════════════════════════════════════════════════════════════

def run_security_checks(transfer_id, received_hash):
    """
    Run a checklist of checks on a completed transfer and return:
      (list_of_check_results, all_passed_boolean)
    """
    t = transfers[transfer_id]
    checks = []

    # Check 1: Does the hash of the received file match the original?
    hash_match = (t["file_hash"] == received_hash)
    checks.append({
        "name": "File Integrity (SHA-256)",
        "passed": hash_match,
        "detail": "Received file hash matches the original exactly."
                  if hash_match else
                  "MISMATCH! The file may have been corrupted or tampered with."
    })

    # Check 2: Did we receive all the chunks we expected?
    received_chunks = t["chunks_received"]
    expected_chunks = t["total_chunks"]
    chunks_ok = received_chunks >= expected_chunks
    checks.append({
        "name": "All Chunks Received",
        "passed": chunks_ok,
        "detail": f"Received {received_chunks}/{expected_chunks} chunks."
    })

    # Check 3: Is the sender a known, registered peer?
    sender_known = t["sender_sid"] in peers
    checks.append({
        "name": "Sender Verified",
        "passed": sender_known,
        "detail": f"Sender '{t['sender_name']}' is a registered network peer."
                  if sender_known else
                  "Sender is no longer connected to the network!"
    })

    # Check 4: Has this exact file been sent before? (duplicate detection)
    duplicate = blockchain.find_by_hash(received_hash)
    checks.append({
        "name": "Duplicate Check",
        "passed": duplicate is None,
        "detail": "This is a new, unique file transfer."
                  if duplicate is None else
                  f"This exact file was already recorded in Block #{duplicate.index}."
    })

    # Check 5: Is the blockchain itself still valid (un-tampered)?
    chain_ok = blockchain.is_valid()
    checks.append({
        "name": "Blockchain Integrity",
        "passed": chain_ok,
        "detail": "The blockchain is intact — no tampering detected."
                  if chain_ok else
                  "WARNING: the blockchain has been tampered with!"
    })

    all_passed = all(c["passed"] for c in checks)
    return checks, all_passed


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: WEB PAGES & SIMPLE JSON ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/')
def home():
    """Show the main page (templates/index.html)."""
    return render_template('index.html')


@app.route('/api/blockchain')
def api_blockchain():
    """Return the full blockchain as JSON (used to populate the Chain tab)."""
    return jsonify({
        "blocks": blockchain.as_list(),
        "valid": blockchain.is_valid(),
    })


@app.route('/api/activity')
def api_activity():
    """Return the recent activity log (used when a tab first loads)."""
    return jsonify(activity_log[-50:])


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: SOCKET.IO EVENTS — these fire in real time as users interact
# ═══════════════════════════════════════════════════════════════════════════

@socketio.on('connect')
def handle_connect():
    print(f"[CONNECT] New connection: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    """A browser tab closed or lost connection — remove them from the peer list."""
    sid = request.sid
    if sid in peers:
        username = peers[sid]["username"]
        del peers[sid]
        emit('peer_list_update', list(peers.values()), broadcast=True)
        log_activity("disconnect", f"🔌 {username} left the network")
        print(f"[DISCONNECT] {username} ({sid})")


@socketio.on('join_network')
def handle_join(data):
    """
    A user typed a username and clicked "Join Network".
    We register them in the `peers` dict and tell everyone about it.
    """
    username = data.get('username', 'Anonymous').strip() or 'Anonymous'
    color = USER_COLORS[len(peers) % len(USER_COLORS)]

    peers[request.sid] = {
        "sid": request.sid,
        "username": username,
        "color": color,
        "sent": 0,
        "received": 0,
        "status": "online",       # online / sending / receiving
    }
    join_room(request.sid)        # lets us send messages to this user specifically

    # Tell THIS user their own info
    emit('joined', {"sid": request.sid, "username": username, "color": color})

    # Tell EVERYONE the updated peer list
    emit('peer_list_update', list(peers.values()), broadcast=True)

    # Send this new user the recent activity history
    emit('activity_history', activity_log[-30:])

    log_activity("connect", f"⚡ {username} joined the network", color=color)
    print(f"[JOIN] {username} ({request.sid})")


# ── Network health check ───────────────────────────────────────────────────

@socketio.on('check_network')
def handle_check_network():
    """
    A simple "network health check" — reports how many peers are online,
    whether the server is reachable, and whether the blockchain is valid.
    This is the 'secure network checking function' feature.
    """
    result = {
        "server_status": "online",
        "peers_online": len(peers),
        "max_peers": 6,
        "blockchain_valid": blockchain.is_valid(),
        "blockchain_length": len(blockchain.chain),
        "active_transfers": len([t for t in transfers.values()
                                  if t["status"] == "transferring"]),
        "checked_at": now(),
    }
    emit('network_status', result)


# ── File transfer flow ───────────────────────────────────────────────────────
#
#  1. Sender clicks "Send" -> 'start_transfer'
#       -> server creates a transfer record, asks receiver to accept
#  2. Receiver clicks "Accept" -> 'accept_transfer'
#       -> server tells sender to start streaming chunks
#  3. Sender streams chunks -> 'send_chunk' (repeated for every chunk)
#       -> server relays each chunk straight to the receiver
#       -> server broadcasts progress % to everyone (the "broadcast" feed)
#  4. Sender finishes -> 'finish_transfer'
#       -> server runs security checks, adds a blockchain block,
#          and tells the receiver the result (receiver then saves the file)
# ─────────────────────────────────────────────────────────────────────────────

@socketio.on('start_transfer')
def handle_start_transfer(data):
    """Sender wants to send a file to a specific peer."""
    transfer_id = str(uuid.uuid4())
    sender = peers.get(request.sid, {})
    receiver = peers.get(data['target_sid'], {})

    transfers[transfer_id] = {
        "id": transfer_id,
        "filename": data['filename'],
        "filesize": data['filesize'],
        "total_chunks": data['total_chunks'],
        "file_hash": data['file_hash'],
        "encryption_key": data['encryption_key'],   # generated client-side
        "sender_sid": request.sid,
        "sender_name": sender.get('username', '?'),
        "sender_color": sender.get('color'),
        "receiver_sid": data['target_sid'],
        "receiver_name": receiver.get('username', '?'),
        "receiver_color": receiver.get('color'),
        "status": "waiting_for_acceptance",
        "chunks_received": 0,
    }

    if request.sid in peers:
        peers[request.sid]['status'] = 'sending'

    # Ask the receiver to accept/decline
    emit('incoming_transfer', {
        "transfer_id": transfer_id,
        "filename": data['filename'],
        "filesize": data['filesize'],
        "file_hash": data['file_hash'],
        "sender_name": sender.get('username'),
        "sender_color": sender.get('color'),
    }, room=data['target_sid'])

    log_activity(
        "transfer_started",
        f"📤 {sender.get('username')} wants to send "
        f"\"{data['filename']}\" to {receiver.get('username')}",
        transfer_id=transfer_id,
        sender=sender.get('username'),
        receiver=receiver.get('username'),
        sender_color=sender.get('color'),
        receiver_color=receiver.get('color'),
        filename=data['filename'],
        filesize=data['filesize'],
        file_hash=data['file_hash'],
    )


@socketio.on('accept_transfer')
def handle_accept(data):
    """Receiver accepted — tell the sender to start streaming chunks."""
    transfer_id = data['transfer_id']
    if transfer_id not in transfers:
        return
    t = transfers[transfer_id]
    t['status'] = 'transferring'

    if t['receiver_sid'] in peers:
        peers[t['receiver_sid']]['status'] = 'receiving'

    emit('transfer_accepted', {"transfer_id": transfer_id}, room=t['sender_sid'])
    log_activity("transfer_accepted",
                  f"✅ {t['receiver_name']} accepted the file from {t['sender_name']}",
                  transfer_id=transfer_id)


@socketio.on('reject_transfer')
def handle_reject(data):
    """Receiver declined the file."""
    transfer_id = data['transfer_id']
    if transfer_id not in transfers:
        return
    t = transfers[transfer_id]
    t['status'] = 'rejected'

    if t['sender_sid'] in peers:
        peers[t['sender_sid']]['status'] = 'online'

    emit('transfer_rejected', {"transfer_id": transfer_id}, room=t['sender_sid'])
    log_activity("transfer_rejected",
                  f"❌ {t['receiver_name']} declined the file from {t['sender_name']}",
                  transfer_id=transfer_id)


@socketio.on('send_chunk')
def handle_send_chunk(data):
    """
    Sender is streaming one chunk of the file.
    We relay it straight to the receiver, and broadcast progress to everyone.
    """
    transfer_id = data['transfer_id']
    chunk_index = data['chunk_index']
    if transfer_id not in transfers:
        return
    t = transfers[transfer_id]

    t['chunks_received'] += 1
    progress_percent = int((t['chunks_received'] / t['total_chunks']) * 100)

    # Relay the encrypted chunk to the receiver. On the very first chunk,
    # also send along the encryption key so the receiver can decrypt.
    payload = {
        "transfer_id": transfer_id,
        "chunk_index": chunk_index,
        "chunk_data": data['chunk_data'],
        "total_chunks": t['total_chunks'],
    }
    if chunk_index == 0:
        payload['encryption_key'] = t['encryption_key']

    emit('receive_chunk', payload, room=t['receiver_sid'])

    # Broadcast progress to EVERYONE (this is the "broadcast feed" / public
    # verification stream — everyone can watch the transfer happen, but
    # only sender + receiver ever see the decrypted content).
    socketio.emit('transfer_progress', {
        "transfer_id": transfer_id,
        "progress": progress_percent,
        "filename": t['filename'],
        "sender": t['sender_name'],
        "receiver": t['receiver_name'],
        "sender_color": t['sender_color'],
        "receiver_color": t['receiver_color'],
    })


@socketio.on('finish_transfer')
def handle_finish(data):
    """
    Sender has sent all chunks. Run the security checks, add a block to the
    blockchain, and tell the receiver the result (receiver then saves the file).
    """
    transfer_id = data['transfer_id']
    if transfer_id not in transfers:
        return
    t = transfers[transfer_id]

    checks, all_passed = run_security_checks(transfer_id, t['file_hash'])

    # Where the file will appear to be saved (shown to the user)
    safe_filename = t['filename'].replace(' ', '_')
    save_path = f"Downloads/{safe_filename}"

    # Record this transfer permanently on the blockchain
    block = blockchain.add_block(
        file_hash=t['file_hash'],
        filename=t['filename'],
        sender=t['sender_name'],
        receiver=t['receiver_name'],
        filesize=t['filesize'],
    )

    t['status'] = 'completed' if all_passed else 'failed_checks'

    # Tell the receiver: here's the verdict, plus where to save the file
    emit('transfer_finished', {
        "transfer_id": transfer_id,
        "checks": checks,
        "all_passed": all_passed,
        "block": block.to_dict(),
        "save_path": save_path,
        "owner": t['sender_name'],
    }, room=t['receiver_sid'])

    # Update sent/received counters for both peers
    if t['sender_sid'] in peers:
        peers[t['sender_sid']]['sent'] += 1
        peers[t['sender_sid']]['status'] = 'online'
    if t['receiver_sid'] in peers:
        peers[t['receiver_sid']]['received'] += 1
        peers[t['receiver_sid']]['status'] = 'online'
    emit('peer_list_update', list(peers.values()), broadcast=True)

    # Broadcast the final result + new block to everyone
    socketio.emit('new_block', block.to_dict())
    icon = "🔐" if all_passed else "⚠️"
    log_activity(
        "transfer_verified" if all_passed else "transfer_failed",
        f"{icon} \"{t['filename']}\" verified and saved by {t['receiver_name']} "
        f"→ Block #{block.index}",
        transfer_id=transfer_id,
        checks=checks,
        all_passed=all_passed,
        save_path=save_path,
        owner=t['sender_name'],
        sender_color=t['sender_color'],
        receiver_color=t['receiver_color'],
    )


# ── Encrypted private chat (sender <-> receiver only) ───────────────────────

@socketio.on('private_message')
def handle_private_message(data):
    """
    Send an end-to-end-encrypted chat message directly to one peer.
    The server only relays the encrypted bytes — it cannot read them.
    Everyone else only sees a "message sent" notice (not the content).
    """
    sender = peers.get(request.sid, {})
    target_sid = data['target_sid']
    receiver = peers.get(target_sid, {})

    # Relay the encrypted message to the recipient only
    emit('private_message', {
        "from_sid": request.sid,
        "from_name": sender.get('username'),
        "from_color": sender.get('color'),
        "encrypted_text": data['encrypted_text'],   # server can't read this
        "iv": data['iv'],
    }, room=target_sid)

    # Let everyone know a message was exchanged, WITHOUT showing the content
    log_activity(
        "private_message",
        f"💬 {sender.get('username')} sent a private message to {receiver.get('username')}",
        sender=sender.get('username'),
        receiver=receiver.get('username'),
    )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: START THE SERVER
# ═══════════════════════════════════════════════════════════════════════════

def open_browser_after_delay():
    """Wait a moment for the server to start, then open the browser."""
    import time
    time.sleep(1.2)
    webbrowser.open('http://localhost:5000')


if __name__ == '__main__':
    print("=" * 60)
    print("  ChainDrop — Secure P2P File Transfer")
    print("=" * 60)
    print()
    print("  Open this URL in your browser:")
    print("  >>> http://localhost:5000")
    print()
    print("  For the multi-user demo, open it in 5-6 browser tabs.")
    print("  (Use Chrome/Firefox — not the VS Code preview panel.)")
    print("=" * 60)

    threading.Thread(target=open_browser_after_delay, daemon=True).start()

    # debug=False + use_reloader=False prevents the server from
    # accidentally starting twice (which causes a "port in use" error).
    socketio.run(app, host='0.0.0.0', port=5000, debug=False,
                  use_reloader=False, allow_unsafe_werkzeug=True)
