# Quantum Chat — Post-Quantum Secure Messaging (Prototype)

A real-time chat platform built to explore how **post-quantum key encapsulation (KEM)** can protect messaging against *Store-Now-Decrypt-Later* attacks, where adversaries record encrypted traffic today and decrypt it once large quantum computers exist.

> **Status:** academic prototype (final-year B.Tech project). The KEM layer is currently a **simulation of Kyber-512 using RSA-2048-OAEP**, because the `pqcrypto` Kyber bindings were unreliable on the target machines. The KEM interface is designed so that a real ML-KEM (FIPS 203) implementation can be dropped in. See the [Roadmap](#roadmap).

## How it works

```
 Sender                     Flask + Socket.IO relay                  Receiver
   │  1. register → KEM keypair (public key stored server-side)          │
   │  2. encapsulate_dual(pk_receiver, pk_sender)                        │
   │        → shared secret + ciphertext for receiver + ciphertext for sender
   │  3. AES-256-EAX(shared secret, message) → nonce‖tag‖ciphertext      │
   │──────── ciphertext | payload ───────▶ stored & relayed ────────────▶│
   │                                                    4. decapsulate → secret
   │                                                    5. AES-EAX decrypt + verify tag
```

* **Dual encapsulation:** each message's secret is wrapped for both the receiver and the sender, so senders can re-read their own history from any device without a local key cache.
* **Authenticated encryption:** AES-256 in EAX mode, so any tampering with a stored or relayed message fails tag verification.
* **Ciphertext-only storage:** the SQLite `messages` table holds only `KEM-ciphertext | AES-payload` blobs (`show_db.py` prints what an attacker with database access would see).
* **Real-time UX:** Socket.IO events for presence (online / last seen), read receipts and chat history.

## Project structure

| File | Purpose |
|---|---|
| `app.py` | Flask REST "crypto co-processor" (`/api/crypto/*`) + Socket.IO events (register, login, message, read receipts) |
| `pqc.py` | KEM interface: `generate_keys`, `encapsulate`, `decapsulate`, `encapsulate_dual` |
| `encryption.py` | AES-256-EAX message encryption / decryption |
| `database.py` | SQLite schema and queries (users, public keys, messages, read state) |
| `show_db.py` | Dumps the stored (encrypted) messages for demonstration |

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py      # http://127.0.0.1:5000
```

The browser client is served from `static/index.html`.

## Security notes and known limitations

This is a learning prototype, and an honest threat model is part of the project:

* **KEM is simulated.** RSA-2048 is *not* quantum-resistant. It stands in for Kyber-512 until a stable ML-KEM library is integrated.
* **Server-side key generation.** Keypairs are currently generated on the server and the secret key is returned to the client, and decapsulation is offered as a server API. In a true end-to-end design, key generation and decapsulation must happen only on the client.
* **Password storage** uses unsalted SHA-256. This should be replaced by Argon2id or bcrypt.
* **No forward secrecy yet.** One long-term keypair per user.
* Socket events are not authenticated per session, and `debug=True` is enabled. Both are fine for a local demo but not for deployment.

## Roadmap

- [ ] Replace RSA simulation with ML-KEM-768 (FIPS 203) via `liboqs-python`
- [ ] Move key generation and decapsulation to the browser (WASM / WebCrypto)
- [ ] Hybrid X25519 + ML-KEM key exchange
- [ ] Argon2id password hashing and authenticated Socket.IO sessions
- [ ] Double-ratchet style forward secrecy

## Tech stack

Python · Flask · Flask-SocketIO · PyCryptodome · SQLite · JavaScript

---
Built by **E. Mohan Kumar**, B.Tech CSE (Cyber Security), Hindustan Institute of Technology and Science, Chennai.
