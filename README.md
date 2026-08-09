# Gramium — Decentralized Messenger

**Gramium** is a secure, decentralized messenger built on libp2p.  
The project is under active development. The current version provides a fully functional **CLI interface** (GUI is disabled).  

The codebase contains commented fragments related to the **Tox** protocol, but **Tox support is completely disabled** and will be reconsidered in the future.

---

## ✨ Features

- **Fully encrypted local storage** — all data (contacts, messages, keys) is stored in an SQLite database encrypted with **AES‑256‑GCM**.
- **Three authentication methods**:
  1. Master password
  2. Login + password
  3. BIP‑39 seed phrase (12 words)
- **Two network modes**:
  - `speed` — fast operation with NAT port mapping and hole punching
  - `anonymity` — enhanced anonymity via relays (Relay, AutoRelay)
- **Proxy support** — HTTP/HTTPS/SOCKS5 (all traffic goes through the specified proxy)
- **Peer‑to‑Peer** based on **libp2p** with DHT (Kademlia) and secure **Noise** transport.
- **Contact and message management** — add, remove, view profiles, message history.
- **Public IP information** with geolocation, region, ISP, and timezone (via free `ip-api.com` API).
- **Built-in password change** (for methods 1 and 2).
- **Complete data purge** (wipe) with password confirmation — a "nuclear" reset function.

---

## 🚀 Installation and Build

### Prerequisites
- **Go** 1.21 or higher
- Dependencies (managed via `go.mod`):
  - `github.com/libp2p/go-libp2p`
  - `github.com/libp2p/go-libp2p-kad-dht`
  - `github.com/sirupsen/logrus`
  - `github.com/tyler-smith/go-bip39`
  - `golang.org/x/term`
  - `modernc.org/sqlite`

### Build
```bash
git clone https://github.com/MirasakaDrakon/gramium.git
cd gramium
go mod tidy
go build -o gramium ./frontend
```

On Windows:
```cmd
git clone https://github.com/MirasakaDrakon/gramium.git
cd gramium
go mod tidy
go build -o gramium.exe ./frontend
```

The resulting binary `gramium` (or `gramium.exe` on Windows) is ready to run.

You can start without building:
```bash
git clone https://github.com/MirasakaDrakon/gramium.git
cd gramium
go mod tidy
go run ./frontend -cli
```

---

## 🧭 Usage

### Starting the application

```bash
./gramium -cli
```

The `-cli` flag is mandatory because GUI mode is currently disabled.

### Proxy
If needed, specify a proxy server:
```bash
./gramium -cli --proxy=socks5://127.0.0.1:1080
# or
./gramium -cli --proxy=http://proxy.example.com:8080
```

### First run
On the first run, the program will:
- Create the `~/.gramium/` directory
- Prompt you to choose an authentication method (1, 2, or 3)
- Ask for password/login/seed phrase (depending on the method)
- Generate a libp2p key pair (Ed25519)
- Create the encrypted database `encrypted-gramium.db` and the meta file `meta.json`

> ⚠️ **Warning!** If you forget your password, login, or seed phrase, **recovery is impossible**.  
> The seed phrase (method 3) must be stored in a safe place.

---

## ⌨️ Available CLI Commands

All commands are entered in interactive mode after startup. The prefix `/` is mandatory for system commands.

### 📘 Basic Commands

| Command | Description |
|---------|-------------|
| `/help` | Show detailed help |
| `/exit` | Quit the application |
| `/ip` | Show your public IP with geolocation, ISP, and timezone. If a proxy is used, the IP of the exit node is shown. |

### 👤 Profile & Settings

| Command | Description |
|---------|-------------|
| `/me` | Display your Gramium Peer ID and all metadata (username, display name, bio, status, client) |
| `/setmeta <key> <value>` | Update a metadata field: `username`, `display_name`, `bio`, `status`.<br>Example: `/setmeta status "away"` |
| `/changepass` | Change password (only for methods 1 and 2) |
| `/switch <mode>` | Switch network mode: `speed` or `anonymity` |

### 👥 Contact Management

| Command | Description |
|---------|-------------|
| `/add <name> <id1> [id2]` | Add a contact. Each ID can be prefixed with `gramium:` (default) or `tox:` (disabled).<br>Example: `/add Alice gramium:12D3KooW...` |
| `/list` | List all contacts with names, statuses, and IDs |
| `/whois <name_or_id>` | Show detailed info about a contact |
| `/remove <name_or_id>` | Delete a contact and all message history with them |
| `/debug` | Dump raw contacts table (id, username, peer_id, tox_id) |

### 💬 Messaging

| Command | Description |
|---------|-------------|
| `/send <to> <message>` | Send a message via Gramium protocol. `<to>` can be a contact name or Peer ID.<br>Example: `/send Alice "Hello!"` |
| `/history <contact> [n]` | Show the last `n` messages (default 20) with the given contact. |

### ⚠️ Dangerous Commands

| Command | Description |
|---------|-------------|
| `/purge` | **Delete ALL data** (contacts, messages, keys, encrypted DB, meta file). Requires password confirmation. The program exits after completion. |

---

## 🧩 Project Architecture

The project consists of three main parts:

1. **`main.go`** — entry point. Parses flags and launches the CLI (or prints a message about GUI being unimplemented).
2. **`cli.go`** — CLI implementation: banner rendering, authentication, command reading, and dispatching to core methods.
3. **`core` package** — contains all business logic:
   - **`node.go`** — main node: libp2p host, DHT, stream handling, sending/receiving messages, contact management.
   - **`auth.go`** — authentication manager: database encryption/decryption using Argon2 and AES‑GCM, password management, key handling.

### 🔐 Security & Encryption

- The **database** is fully encrypted using **AES‑256‑GCM**.
- The encryption key is derived from the password/seed phrase via **Argon2id** with parameters (time=2, memory=64 MB, threads=4).
- Salt (16 bytes) and nonce are generated using a cryptographically secure RNG (`crypto/rand`).
- On database opening, the decrypted file is stored in a temporary directory and removed after closing.
- Password change triggers a full re-encryption of the database.
- The **transport layer** in libp2p is secured with the **Noise** protocol.

### 🌐 Network Modes

- **`speed`** — uses `libp2p.NATPortMap()` and hole punching for direct connections.
- **`anonymity`** — enables `EnableRelay()`, `EnableAutoRelay()`, and hole punching; all requests go through relays.

### 📁 User File Structure

In the home directory (inside `~/.gramium/`), the following files are stored:

- `encrypted-gramium.db` — encrypted SQLite database
- `meta.json` — user metadata (username, display name, bio, status, client version)
- `gramium.log` — application log (using `logrus`)
- `encrypted-gramium.db.meta` — auxiliary file storing the authentication method code

---

## 🧪 Example Session

```bash
$ ./gramium -cli
...
[AUTH] Welcome to Gramium!
Enter your username (account meta): alice

Select an authentication method:
  1. Master key (password)
  2. Login + password
  3. Seed phrase (BIP-39, 12 words)
Your choice (1-3): 1
Create a master key (password):
Repeat the master key:
[OK] Database created and encrypted

> /me
[ID] Gramium: gramium:12D3KooW...
[USER] Username: alice
[STATUS] Status: online
[CLIENT] Client: Gramium-Genesis-CLI v1.0.0

> /add Bob 12D3KooW...
[OK] Contact added: Bob

> /send Bob "Hello from Gramium!"
[OK] Message sent

> /list
[LIST] Contacts:
  - Bob [online] (gramium:12D3KooW...)

> /ip
[IP] Your IP is: 203.0.113.42 (US/California/Los Angeles - 34.0522,-118.2437) ; TZ: America/Los_Angeles ; ISP: Example ISP ; AS/ASN: AS12345

> /exit
[INFO] Goodbye!
```

---

## 🛠 Development & Extending

### Enabling Tox
The code contains commented blocks related to Tox. To enable Tox, you would need to:
1. Uncomment the relevant imports, `Node` struct fields, and methods.
2. Implement or import the `tox` package (currently missing).
3. Add handling of the `tox:` prefix in `/add` and `/send` commands.

### Enabling GUI
The GUI mode in `main.go` is commented out. To activate it, implement the `RunGUI()` function and remove the placeholder.

### Logging
Logs are written to `~/.gramium/gramium.log` in text format with full timestamps. You can change the log level in the code.

---

## 📄 License

This project is distributed under the **GNU General Public License v3.0** (GPL‑3.0).  
See the [LICENSE](LICENSE) file for full details.

---

## 🤝 Contributing & Contact

We welcome suggestions, bug reports, and pull requests.  
For communication with developers, please use the [Issues](https://github.com/MirasakaDrakon/gramium/issues) section on GitHub.

---

**Gramium** — secure, simple, decentralized. Join the development!