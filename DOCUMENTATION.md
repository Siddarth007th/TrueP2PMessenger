# Nomadic Parity Swarm — True P2P Messenger
## Complete Project Documentation

---

## 1. Vision & Research Foundation

The Nomadic Parity Swarm is a research project exploring **serverless, zero-knowledge mesh networking**. The core thesis: can sovereign edge devices communicate, replicate, and recover data without ever trusting a central authority — and can cryptography alone enforce access control instead of server-side permissions?

This prototype proves that thesis by building a fully functional E2EE P2P messenger where:
- Every node is a sovereign daemon (no central server exists)
- Data at rest is always encrypted ciphertext
- Nodes that relay messages they're not party to can never decrypt them (blind vault)
- The mesh is self-healing — nodes discover peers, exchange keys, and route messages autonomously

---

## 2. Research Lineage — How We Got Here

This final prototype is the result of **7 iterative prototypes**, each solving a specific technical challenge. Below is the complete evolution:

### Prototype 1: Tor ECDH PoC (`/prototypes/tor-ecdh-poc/`)
**Goal:** Prove that two Node.js processes can derive a shared AES key over a raw TCP socket using Elliptic Curve Diffie-Hellman.

**What was built:**
- `node-a.js`: Connects to Node B, sends its ECDH `secp256k1` public key, receives B's public key, derives a shared AES-256-GCM secret, encrypts a payload, and transmits the ciphertext.
- `node-b.js`: Listens on TCP port 8080, receives A's public key, sends its own, derives the same shared secret, and decrypts the incoming ciphertext.

**Key Discovery:** ECDH `secp256k1` key exchange works flawlessly over raw `net.connect()` TCP sockets. The shared secret is mathematically identical on both sides without ever transmitting the private key.

---

### Prototype 2: WebRTC Hybrid P2P (`/prototypes/super-node-poc/`)
**Goal:** Prove that WebRTC Data Channels can replace raw UDP for P2P syncing to bypass Tor latency.

**What was built:**
- `signaling.js`: A Socket.IO server acting as the signaling relay for WebRTC SDP offers/answers and ICE candidates.
- `edge-node.js`: A client using `node-datachannel` that connects to the signaling server, discovers peers, and opens direct WebRTC Data Channels.

**Key Discovery:** WebRTC works for P2P, but introduces a mandatory signaling dependency. The "Glare Condition" (both nodes sending offers simultaneously) was solved by enforcing alphabetical sorting — the node with the higher ID always initiates.

---

### Prototype 3: CR-SQLite Database Validation (`/prototypes/crsqlite-poc/`)
**Goal:** Prove that Conflict-Free Replicated SQLite can extract and deterministically merge binary deltas (O(delta)) for the database engine pivot.

**What was built:**
- `db-test.js`: Spins up two in-memory databases using `@vlcn.io/crsqlite-allinone`, upgrades relational schemas to CRRs (Conflict-Free Replicated Relations), inserts diverging offline data, and cross-applies binary deltas.

**Key Discoveries:**
- Node 24 breaks `better-sqlite3` v9.6.0 C++ compilation. Fixed with `"overrides": {"better-sqlite3": "^11.1.2"}` in `package.json`.
- CR-SQLite v0.16.x added `cl` (causal length) and `seq` (sequence number) columns to `crsql_changes`. Initial sync silently failed until the INSERT statement was expanded to include all 9 columns.
- Deterministic merge requires `db.transaction()` wrapping for ACID guarantees during changeset ingestion.

---

### Prototype 4: Parity Notes — Hybrid P2P + E2EE Application (`/prototypes/parity-notes/`)
**Goal:** Prove that the P2P and CR-SQLite concepts can be combined into a functional application with local-first, zero-knowledge sync.

**What was built:**
- Edge Daemons with persistent local CR-SQLite databases
- A React/Vite Glassmorphism frontend for notes
- A Super-Node with its own `cloud.db` CR-SQLite instance for always-online backup
- Dual-Transport Sync: deltas broadcast simultaneously over WebRTC (P2P zero-latency) and Socket.IO (cloud backup)
- Zero-Knowledge Encryption: AES-256-GCM encryption of the `c.val` column before sending payloads to the Super-Node

**Key Discovery:** CR-SQLite can mathematically merge and compact encrypted metadata on a cloud server without ever decrypting or knowing the plaintext values inside the SQLite table.

---

### Prototype 5: Mesh Proof — Single-File Daemon (`/prototypes/mesh-proof.js`)
**Goal:** Collapse the entire mesh network into a single executable file proving ECDH key exchange, AES-256-GCM encryption, blind vault replication, and data recovery — all in 31 lines.

**What was built:**
A single `mesh-proof.js` script that:
1. Creates 3 in-memory SQLite databases (A, B, C)
2. A and B perform ECDH `secp256k1` key exchange and derive a shared AES-256-GCM key
3. A encrypts `TOP_SECRET_DB_RECORD`, saves it locally, sends ciphertext to B (who decrypts) and C (who stores blindly)
4. A wipes its own database
5. A connects to C's vault, retrieves the ciphertext, decrypts it with its AES key, and recovers the original record

**Key Discovery:** A blind vault node (C) that never participates in ECDH can still serve as a disaster recovery backup. The data owner (A) can always recover from C by re-deriving the AES key.

---

### Prototype 6: Centralized Chat Attempt (`/prototypes/server-routed-chat/`)
**Goal:** Build a multi-window chat interface.

**What was built:**
- A central server that routes messages between node clients
- Individual node-client processes with their own UIs

**Critical Failure:** This design violated the core principle of the Nomadic Parity Swarm. A central routing server is a single point of failure and trust. It was abandoned in favor of the true P2P architecture.

---

### Prototype 7: True P2P Messenger — THIS PROJECT (`/prototypes/true-p2p-messenger/`)
**Goal:** The final, complete implementation. Zero centralization. Every node is sovereign.

This is the prototype contained in this folder. Full details below.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NO CENTRAL SERVER                         │
│                    NO SHARED DATABASE                        │
│                    NO ROUTING PROXY                          │
└─────────────────────────────────────────────────────────────┘

  Node A (3001/4001)          Node B (3002/4002)          Node C (3003/4003)
  ┌──────────────┐            ┌──────────────┐            ┌──────────────┐
  │  Express UI  │            │  Express UI  │            │  Express UI  │
  │  Socket.IO   │            │  Socket.IO   │            │  Socket.IO   │
  ├──────────────┤            ├──────────────┤            ├──────────────┤
  │  TCP Server  │◄──────────►│  TCP Server  │◄──────────►│  TCP Server  │
  │  (port 4001) │   raw TCP  │  (port 4002) │   raw TCP  │  (port 4003) │
  ├──────────────┤            ├──────────────┤            ├──────────────┤
  │  node-A.db   │            │  node-B.db   │            │  node-C.db   │
  │  (SQLite)    │            │  (SQLite)    │            │  (SQLite)    │
  └──────────────┘            └──────────────┘            └──────────────┘
       ▲                           ▲                           ▲
       │                           │                           │
       ▼                           ▼                           ▼
  ┌──────────┐               ┌──────────┐               ┌──────────┐
  │ Chat UI  │               │ Chat UI  │               │ Chat UI  │
  │ Server   │               │ Server   │               │ Server   │
  │ Dashboard│               │ Dashboard│               │ Dashboard│
  └──────────┘               └──────────┘               └──────────┘
```

Each node is a completely isolated process running:
- **Express HTTP Server** — serves the chat UI and server dashboard
- **Socket.IO WebSocket** — real-time UI updates
- **TCP Mesh Socket** — raw `net.createServer()` / `net.connect()` for P2P routing
- **SQLite Database** — isolated `better-sqlite3` instance (`node-A.db`, `node-B.db`, `node-C.db`)

---

## 4. Cryptography — The State Machine

### Step 1: ECDH secp256k1 Key Exchange
On boot, each node generates an ephemeral ECDH keypair on the `secp256k1` curve (the same curve used by Bitcoin):

```
ecdh = crypto.createECDH('secp256k1')
ecdh.generateKeys()
```

### Step 2: TCP Handshake
When a TCP connection is established between two nodes, both sides immediately send a `hello` message containing their public key:

```
→  {"t":"hello","n":"A","pk":"04a1b2c3..."}
←  {"t":"hello","n":"B","pk":"04d4e5f6..."}
```

### Step 3: Shared Secret Derivation
Each side computes the shared secret using their private key and the peer's public key, then hashes it into a 256-bit AES key:

```
sharedSecret = ecdh.computeSecret(peerPublicKey)
aesKey = SHA-256(sharedSecret)
```

The mathematical property of ECDH guarantees that A's derived key equals B's derived key, without either side ever transmitting their private key.

### Step 4: AES-256-GCM Encryption
Every message is encrypted using AES-256-GCM (Galois/Counter Mode), which provides both confidentiality and authenticity:

```
Encrypt → { nonce (12 bytes), tag (16 bytes), val (ciphertext) }
```

The nonce is a cryptographically random 12-byte IV generated fresh for every single message. The auth tag prevents tampering.

### Step 5: UI Blocking
The frontend chat input and peer buttons remain **strictly disabled** until the backend confirms that the ECDH handshake with each specific peer is complete. This eliminates the "no key for peer" race condition from earlier prototypes.

---

## 5. Message Flow

### Direct Message (A → B)

1. Node A encrypts plaintext with B's AES key → produces `{nonce, tag, val}`
2. A stores the ciphertext in its own local SQLite vault
3. A broadcasts the ciphertext to **ALL** peers via TCP (B and C both receive it)
4. **Node B:** Sees `toNode === 'B'`, has A's AES key → **decrypts and displays plaintext**
5. **Node C:** Sees `toNode !== 'C'` → **stores raw ciphertext as blind backup, never decrypts**

### Group Message (A → B, C)

1. Node A encrypts the plaintext **twice** — once with B's AES key, once with C's AES key
2. This produces two separate ciphertext payloads with different nonces, tags, and vals
3. A broadcasts both payloads to all peers
4. **Node B:** Decrypts the copy addressed to B; stores the copy addressed to C as blind backup
5. **Node C:** Decrypts the copy addressed to C; stores the copy addressed to B as blind backup

### Blind Vault Replication

When a node receives a message that is NOT addressed to it:
- It writes the raw ciphertext (nonce, tag, val) to its local SQLite vault
- It does NOT attempt to decrypt it (it lacks the AES key for that conversation)
- It does NOT display it in the chat UI
- This provides distributed backup without compromising confidentiality

---

## 6. The Server Dashboard — My Work vs. Locker

Each node serves a separate dashboard page at `/server.html` with two tabs:

### My Work Tab
Queries the local SQLite vault for rows where `fromNode === thisNode OR toNode === thisNode`. Since the node participated in these conversations, it holds the AES key and can decrypt them. The dashboard displays the **decrypted plaintext**.

### Locker Tab
Queries the local SQLite vault for rows where `fromNode !== thisNode AND toNode !== thisNode`. These are blind replications from conversations the node was NOT part of. The node does NOT hold the AES key for these conversations. The dashboard displays the **raw encrypted ciphertext** (nonce, tag, val).

This split proves the zero-knowledge property: every node stores data from all conversations in the mesh, but can only read the ones it participated in.

---

## 7. SQLite Vault Schema

```sql
CREATE TABLE vault (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  msgId     TEXT UNIQUE,    -- UUID preventing duplicate ingestion
  fromNode  TEXT,           -- sender node name (A, B, or C)
  toNode    TEXT,           -- intended recipient node name
  nonce     TEXT,           -- 12-byte random IV (hex)
  tag       TEXT,           -- 16-byte GCM auth tag (hex)
  val       TEXT,           -- AES-256-GCM ciphertext (hex)
  ts        INTEGER         -- Unix timestamp
);
```

---

## 8. File Reference

| File | Lines | Purpose |
|------|-------|---------|
| `node-daemon.js` | 42 | The sovereign node daemon. Runs Express, TCP mesh, SQLite, ECDH/AES. |
| `public/index.html` | ~70 | Clean 2-panel chat UI. Contacts on left, messages on right. |
| `public/server.html` | ~66 | Server dashboard. My Work (decrypted) + Locker (encrypted) tabs. |
| `launcher.js` | 11 | Spawns 3 isolated node processes, opens 6 browser tabs. |

---

## 9. How to Run

```bash
node launcher.js
```

This will:
1. Delete any stale `.db` files from previous runs
2. Spawn Node A (UI: 3001, TCP: 4001)
3. Spawn Node B (UI: 3002, TCP: 4002)
4. Spawn Node C (UI: 3003, TCP: 4003)
5. Open 6 browser tabs (chat + server dashboard per node)

The nodes will automatically:
- Bind their TCP mesh servers
- Connect to each other with retry logic (500ms backoff)
- Exchange ECDH public keys over raw TCP
- Derive AES-256-GCM shared secrets
- Unlock the UI once all handshakes complete

---

## 10. Verified Test Results

An automated headless test was run to verify the complete flow:

```
PASS: B My Work has A→B msg
PASS: B My Work is DECRYPTED
PASS: B Locker has blind A→C copy
PASS: B Locker is RAW CIPHERTEXT
PASS: C My Work has A→C msg
PASS: C My Work is DECRYPTED
PASS: C Locker has blind A→B copy
PASS: C Locker is RAW CIPHERTEXT (not plaintext)
=============================
Passed: 12 | Failed: 0
```

---

## 11. Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `express` | ^5.x | HTTP server for serving UI |
| `socket.io` | ^4.x | Real-time WebSocket for UI updates |
| `better-sqlite3` | ^11.x | Synchronous SQLite3 bindings for Node.js |

All cryptography uses Node.js native `crypto` module — no third-party crypto libraries.

---

## 12. What This Proves

1. **Zero Centralization:** No central server, router, or shared database exists in the system.
2. **Zero-Knowledge at Rest:** Every row in every node's SQLite database contains only encrypted ciphertext, nonces, and auth tags. Plaintext never touches disk.
3. **Cryptographic Access Control:** Only the intended recipient can decrypt a message. Access is enforced by mathematics (ECDH key derivation), not by server-side permissions.
4. **Blind Vault Replication:** Nodes faithfully store and replicate ciphertexts from conversations they're not party to, enabling distributed backup without compromising confidentiality.
5. **Self-Healing Mesh:** Nodes auto-discover peers, retry failed connections, and complete the ECDH handshake autonomously. The UI strictly blocks until the mesh is secured.
