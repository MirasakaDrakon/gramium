package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"
    "time"

    "github.com/sirupsen/logrus"
    "github.com/tyler-smith/go-bip39"
    "golang.org/x/term"

    "gramium/core"
)

func main() {
    home, err := os.UserHomeDir()
    if err != nil {
        fmt.Printf("[WARN] Failed to retrieve home directory: %v\n", err)
        home = "."
    }
    logDir := filepath.Join(home, ".gramium")
    if err := os.MkdirAll(logDir, 0700); err != nil {
        fmt.Printf("[WARN] Failed to create log folder: %v\n", err)
    } else {
        logPath := filepath.Join(logDir, "gramium.log")
        logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
        if err != nil {
            fmt.Printf("[WARN] Failed to open log file: %v\n", err)
        } else {
            logrus.SetOutput(logFile)
            logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
            log.SetOutput(logFile)
        }
    }

    dbPath := filepath.Join(home, ".gramium", "encrypted-gramium.db")
    metaFile := filepath.Join(home, ".gramium", "meta.json")
    os.MkdirAll(filepath.Join(home, ".gramium"), 0700)

    var isNewDB bool
    if _, err := os.Stat(dbPath); err != nil {
        isNewDB = true
    }

    authManager := core.NewAuthManager(dbPath)
    var password string
    var meta *core.PeerMeta

    meta = &core.PeerMeta{
        ClientName:    "Gramium-Genesis-CLI",
        ClientVersion: "1.0.0",
        Status:        "online",
    }
    if data, err := os.ReadFile(metaFile); err == nil {
        json.Unmarshal(data, meta)
    }

    if isNewDB {
        fmt.Println("[AUTH] Welcome to Gramium!")
        fmt.Print("Enter your username (account meta): ")
        scanner := bufio.NewScanner(os.Stdin)
        scanner.Scan()
        username := strings.TrimSpace(scanner.Text())
        if username == "" {
            username = "user"
        }
        meta.Username = username

        fmt.Println("\nSelect an authentication method:")
        fmt.Println("  1. Master key (password)")
        fmt.Println("  2. Username (auth) + password")
        fmt.Println("  3. Seed phrase (BIP-39, 12 words)")
        fmt.Println("  4. AES-256 certificate file (key.pem)")
        fmt.Print("Your choice (1-4): ")
        scanner.Scan()
        methodStr := strings.TrimSpace(scanner.Text())
        method, _ := strconv.Atoi(methodStr)
        if method < 1 || method > 4 {
            method = 1
        }

        switch method {
        case 1:
            fmt.Print("Create a master key (password): ")
            pw1, _ := term.ReadPassword(int(syscall.Stdin))
            fmt.Println()
            fmt.Print("Repeat the master key: ")
            pw2, _ := term.ReadPassword(int(syscall.Stdin))
            fmt.Println()
            if string(pw1) != string(pw2) {
                fmt.Println("[ERROR] Passwords do not match!")
                os.Exit(1)
            }
            password = string(pw1)

        case 2:
            fmt.Print("Enter username (auth): ")
            scanner.Scan()
            login := strings.TrimSpace(scanner.Text())
            if login == "" {
                login = "user"
            }
            fmt.Print("Enter password: ")
            pw1, _ := term.ReadPassword(int(syscall.Stdin))
            fmt.Println()
            fmt.Print("Repeat the password: ")
            pw2, _ := term.ReadPassword(int(syscall.Stdin))
            fmt.Println()
            if string(pw1) != string(pw2) {
                fmt.Println("[ERROR] Passwords do not match!")
                os.Exit(1)
            }
            password = login + ";" + string(pw1)

        case 3:
            entropy, _ := bip39.NewEntropy(128)
            mnemonic, _ := bip39.NewMnemonic(entropy)
            fmt.Println("\nYour seed phrase (keep it safe):")
            fmt.Println("============================================")
            fmt.Println(mnemonic)
            fmt.Println("============================================")
            fmt.Print("\nPress Enter to continue...")
            scanner.Scan()
            password = mnemonic

        case 4:
            fmt.Print("Enter the path to the certificate file (key.pem): ")
            scanner.Scan()
            certPath := strings.TrimSpace(scanner.Text())
            data, err := os.ReadFile(certPath)
            if err != nil {
                fmt.Printf("[ERROR] Failed to read file: %v\n", err)
                os.Exit(1)
            }
            password = string(data)
        }

        data, _ := json.Marshal(meta)
        os.WriteFile(metaFile, data, 0600)

        if err := authManager.CreateDatabase(password, meta, method); err != nil {
            fmt.Printf("[ERROR] Database creation failed: %v\n", err)
            os.Exit(1)
        }

    } else {
        method, err := authManager.LoadAuthMeta()
        if err != nil {
            fmt.Printf("[ERROR] Failed to load authentication method: %v\n", err)
            os.Exit(1)
        }

        scanner := bufio.NewScanner(os.Stdin)

        switch method {
        case 1:
            fmt.Print("[AUTH] Enter master key: ")
            pw, _ := term.ReadPassword(int(syscall.Stdin))
            fmt.Println()
            password = string(pw)

        case 2:
            fmt.Print("[AUTH] Enter username (auth): ")
            scanner.Scan()
            login := strings.TrimSpace(scanner.Text())
            fmt.Print("[AUTH] Enter password: ")
            pw, _ := term.ReadPassword(int(syscall.Stdin))
            fmt.Println()
            password = login + ";" + string(pw)

        case 3:
            fmt.Print("[AUTH] Enter seed phrase (12 words): ")
            scanner.Scan()
            password = strings.TrimSpace(scanner.Text())

        case 4:
            fmt.Print("[AUTH] Enter the path to the certificate file (key.pem): ")
            scanner.Scan()
            certPath := strings.TrimSpace(scanner.Text())
            data, err := os.ReadFile(certPath)
            if err != nil {
                fmt.Printf("[ERROR] Failed to read file: %v\n", err)
                os.Exit(1)
            }
            password = string(data)
        }

        if data, err := os.ReadFile(metaFile); err == nil {
            json.Unmarshal(data, meta)
        }
    }

    cfg := &core.Config{
        Mode:   "speed",
        DBPath: dbPath,
    }
    if len(os.Args) > 1 && os.Args[1] == "--anonymity" {
        cfg.Mode = "anonymity"
    }

    node, err := core.NewNode(cfg, password, meta)
    if err != nil {
        fmt.Printf("[ERROR] Startup failed: %v\n", err)
        os.Exit(1)
    }
    password = ""
    node.Start()
    defer node.Stop()

    fmt.Println("\n[INFO] Enter a command (/help for list)")
    scanner := bufio.NewScanner(os.Stdin)

    for {
        fmt.Print("> ")
        if !scanner.Scan() {
            break
        }
        input := strings.TrimSpace(scanner.Text())
        if input == "" {
            continue
        }
        fields := strings.Fields(input)
        if len(fields) == 0 {
            continue
        }
        cmd := fields[0]

        switch cmd {
        case "/help":
            fmt.Println(`
Available commands:
  /help                - this help
  /me                  - show my IDs and metadata
  /setmeta <key> <value> - set metadata field (username, display_name, bio, status)
  /changepass          - change password
  /switch <mode>       - switch mode (speed / anonymity)
  /add <name> <peerid> [tox_id] - add a contact
  /list                - show contact list
  /whois <name>        - show contact information
  /send <gramium|tox> <to> <msg> - send a message via the selected protocol
  /history <contact> [count] - show chat history
  /remove <contact>    - remove a contact
  /debug               - show raw contact data (for debugging)
  /purge               - completely delete all data (requires password and confirmation)
  /exit                - exit
`)
        case "/me":
            ids := node.GetIDs()
            fmt.Printf("[ID] Gramium: %s\n", ids["gramium"])
            if toxID, ok := ids["tox"]; ok {
                fmt.Printf("[TOX] Tox ID: %s\n", toxID)
            } else {
                fmt.Println("[TOX] Tox is not running")
            }
            m := node.GetMyMeta()
            fmt.Printf("[USER] Username: %s\n", m.Username)
            if m.DisplayName != "" {
                fmt.Printf("[DISPLAY] Display name: %s\n", m.DisplayName)
            }
            if m.Bio != "" {
                fmt.Printf("[BIO] Bio: %s\n", m.Bio)
            }
            fmt.Printf("[STATUS] Status: %s\n", m.Status)
            fmt.Printf("[CLIENT] Client: %s v%s\n", m.ClientName, m.ClientVersion)

        case "/setmeta":
            if len(fields) < 3 {
                fmt.Println("[ERROR] Usage: /setmeta <key> <value>")
                continue
            }
            key := fields[1]
            value := strings.Join(fields[2:], " ")
            m := node.GetMyMeta()
            switch key {
            case "username":
                m.Username = value
            case "display_name":
                m.DisplayName = value
            case "bio":
                m.Bio = value
            case "status":
                m.Status = value
            default:
                fmt.Println("[ERROR] Allowed keys: username, display_name, bio, status")
                continue
            }
            node.SetMyMeta(m)
            data, _ := json.Marshal(m)
            os.WriteFile(metaFile, data, 0600)
            fmt.Println("[OK] Metadata updated")

        case "/changepass":
            method, err := node.AuthManager.LoadAuthMeta()
            if err != nil {
                fmt.Println("[ERROR] Failed to determine authentication method")
                continue
            }
            if method != 1 && method != 2 {
                fmt.Println("[ERROR] Password change is only allowed for method 1 (master key) and method 2 (username+password)")
                continue
            }

            fmt.Print("[AUTH] Current password: ")
            oldPw, _ := term.ReadPassword(int(syscall.Stdin))
            fmt.Println()
            fmt.Print("[AUTH] New password: ")
            newPw, _ := term.ReadPassword(int(syscall.Stdin))
            fmt.Println()
            fmt.Print("[AUTH] Repeat new password: ")
            confirmPw, _ := term.ReadPassword(int(syscall.Stdin))
            fmt.Println()
            if string(newPw) != string(confirmPw) {
                fmt.Println("[ERROR] Passwords do not match")
                continue
            }
            if err := node.AuthManager.ChangePassword(string(oldPw), string(newPw)); err != nil {
                fmt.Printf("[ERROR] Password change failed: %v\n", err)
            } else {
                fmt.Println("[OK] Password changed successfully")
            }

        case "/switch":
            if len(fields) < 2 {
                fmt.Println("[ERROR] Specify mode: speed or anonymity")
                continue
            }
            mode := fields[1]
            if mode != "speed" && mode != "anonymity" {
                fmt.Println("[ERROR] Mode must be speed or anonymity")
                continue
            }
            if err := node.SwitchMode(mode); err != nil {
                fmt.Printf("[ERROR] Switch failed: %v\n", err)
            } else {
                fmt.Printf("[OK] Switched to mode: %s\n", mode)
            }

        case "/add":
            if len(fields) < 3 {
                fmt.Println("[ERROR] Usage: /add <name> <peer_id> [tox_id]")
                continue
            }
            name := fields[1]
            var peerID, toxID string
            if len(fields) == 3 {
                peerID = ""
                toxID = fields[2]
            } else {
                peerID = fields[2]
                toxID = fields[3]
            }
            if err := node.AddContact(name, peerID, toxID); err != nil {
                fmt.Printf("[ERROR] Failed to add contact: %v\n", err)
            } else {
                fmt.Printf("[OK] Contact added: %s\n", name)
            }

        case "/list":
            contacts, err := node.ListContacts()
            if err != nil {
                fmt.Printf("[ERROR] Failed to get contact list: %v\n", err)
                continue
            }
            if len(contacts) == 0 {
                fmt.Println("[INFO] No contacts")
            } else {
                fmt.Println("[LIST] Contacts:")
                for _, c := range contacts {
                    fmt.Println("  -", c)
                }
            }

        case "/whois":
            if len(fields) < 2 {
                fmt.Println("[ERROR] Usage: /whois <name_or_peerid>")
                continue
            }
            name := fields[1]
            m, err := node.GetContactMeta(name)
            if err != nil {
                fmt.Printf("[ERROR] Contact not found or no metadata: %v\n", err)
                continue
            }
            fmt.Printf("[USER] Username: %s\n", m.Username)
            if m.DisplayName != "" {
                fmt.Printf("[DISPLAY] Display name: %s\n", m.DisplayName)
            }
            if m.Bio != "" {
                fmt.Printf("[BIO] Bio: %s\n", m.Bio)
            }
            if m.AvatarHash != "" {
                fmt.Printf("[AVATAR] Avatar hash: %s\n", m.AvatarHash)
            }
            fmt.Printf("[STATUS] Status: %s\n", m.Status)
            fmt.Printf("[CLIENT] Client: %s v%s", m.ClientName, m.ClientVersion)
            if m.ClientOS != "" {
                fmt.Printf(" (%s)", m.ClientOS)
            }
            fmt.Println()
            if len(m.Features) > 0 {
                fmt.Printf("[FEATURES] Features: %v\n", m.Features)
            }

        case "/send":
            if len(fields) < 4 {
                fmt.Println("[ERROR] Usage: /send <gramium|tox> <to> <message>")
                continue
            }
            protocol := fields[1]
            to := fields[2]
            message := strings.Join(fields[3:], " ")
            if protocol != "gramium" && protocol != "tox" {
                fmt.Println("[ERROR] Protocol must be gramium or tox")
                continue
            }
            if err := node.SendMessage(to, []byte(message), protocol); err != nil {
                fmt.Printf("[ERROR] Send failed: %v\n", err)
            } else {
                fmt.Printf("[OK] Message sent via %s\n", protocol)
            }

        case "/history":
            if len(fields) < 2 {
                fmt.Println("[ERROR] Usage: /history <contact> [count]")
                continue
            }
            identifier := fields[1]
            limit := 20
            if len(fields) > 2 {
                if l, err := strconv.Atoi(fields[2]); err == nil && l > 0 {
                    limit = l
                }
            }
            var contactID int
            err := node.DB.QueryRow("SELECT id FROM contacts WHERE username = ? OR peer_id = ? OR tox_id = ?", identifier, identifier, identifier).Scan(&contactID)
            if err != nil {
                fmt.Println("[ERROR] Contact not found")
                continue
            }
            rows, err := node.DB.Query(`
                SELECT is_outgoing, message, timestamp
                FROM messages
                WHERE contact_id = ?
                ORDER BY timestamp DESC LIMIT ?
            `, contactID, limit)
            if err != nil {
                fmt.Printf("[ERROR] Failed to read history: %v\n", err)
                continue
            }
            defer rows.Close()
            var msgs []string
            for rows.Next() {
                var outgoing bool
                var msg string
                var ts int64
                rows.Scan(&outgoing, &msg, &ts)
                direction := "→"
                if !outgoing {
                    direction = "←"
                }
                t := time.Unix(ts, 0).Format("15:04:05")
                msgs = append(msgs, fmt.Sprintf("%s [%s] %s", direction, t, msg))
            }
            if len(msgs) == 0 {
                fmt.Println("[INFO] No messages with this contact")
            } else {
                fmt.Println("[HISTORY] Messages:")
                for i := len(msgs) - 1; i >= 0; i-- {
                    fmt.Println("  ", msgs[i])
                }
            }

        case "/remove":
            if len(fields) < 2 {
                fmt.Println("[ERROR] Usage: /remove <name_or_id>")
                continue
            }
            identifier := fields[1]
            tx, err := node.DB.Begin()
            if err != nil {
                fmt.Printf("[ERROR] Transaction start failed: %v\n", err)
                continue
            }
            _, err = tx.Exec("DELETE FROM messages WHERE contact_id = (SELECT id FROM contacts WHERE username = ? OR peer_id = ? OR tox_id = ?)", identifier, identifier, identifier)
            if err != nil {
                tx.Rollback()
                fmt.Printf("[ERROR] Failed to delete messages: %v\n", err)
                continue
            }
            _, err = tx.Exec("DELETE FROM contacts WHERE username = ? OR peer_id = ? OR tox_id = ?", identifier, identifier, identifier)
            if err != nil {
                tx.Rollback()
                fmt.Printf("[ERROR] Failed to delete contact: %v\n", err)
                continue
            }
            if err := tx.Commit(); err != nil {
                fmt.Printf("[ERROR] Commit failed: %v\n", err)
            } else {
                fmt.Println("[OK] Contact removed")
            }

        case "/debug":
            lines, err := node.DebugContacts()
            if err != nil {
                fmt.Printf("[ERROR] %v\n", err)
                continue
            }
            fmt.Println("[DEBUG] Contacts table contents:")
            for _, l := range lines {
                fmt.Println("  ", l)
            }

        case "/purge":
            fmt.Print("[WARNING] Are you sure you want to delete all data (contacts, history, keys)? (y/N): ")
            scanner := bufio.NewScanner(os.Stdin)
            scanner.Scan()
            confirm := strings.TrimSpace(scanner.Text())
            if confirm != "y" && confirm != "Y" {
                fmt.Println("[INFO] Operation cancelled")
                continue
            }

            method, err := node.AuthManager.LoadAuthMeta()
            if err != nil {
                fmt.Printf("[ERROR] Failed to determine authentication method: %v\n", err)
                continue
            }

            var purgePassword string

            switch method {
            case 1:
                fmt.Print("[AUTH] Enter master key: ")
                pw, _ := term.ReadPassword(int(syscall.Stdin))
                fmt.Println()
                purgePassword = string(pw)

            case 2:
                fmt.Print("[AUTH] Enter username (auth): ")
                scanner.Scan()
                login := strings.TrimSpace(scanner.Text())
                fmt.Print("[AUTH] Enter password: ")
                pw, _ := term.ReadPassword(int(syscall.Stdin))
                fmt.Println()
                purgePassword = login + ";" + string(pw)

            case 3:
                fmt.Print("[AUTH] Enter seed phrase (12 words): ")
                scanner.Scan()
                purgePassword = strings.TrimSpace(scanner.Text())

            case 4:
                fmt.Print("[AUTH] Enter the path to the certificate file (key.pem): ")
                scanner.Scan()
                certPath := strings.TrimSpace(scanner.Text())
                data, err := os.ReadFile(certPath)
                if err != nil {
                    fmt.Printf("[ERROR] Failed to read file: %v\n", err)
                    continue
                }
                purgePassword = string(data)
            }

            if err := node.AuthManager.PurgeDatabase(purgePassword); err != nil {
                fmt.Printf("[ERROR] Purge failed: %v\n", err)
                continue
            }

            fmt.Println("[OK] All data deleted. Program will exit.")
            node.Stop()
            return

        case "/exit":
            fmt.Println("[INFO] Goodbye!")
            return

        default:
            fmt.Println("[ERROR] Unknown command. Type /help")
        }
    }
}