//IMPORTANT NOTE: TOX SUPPPORT IS DISABLED, BUT DO NOT REMOVE THE COMMENTED CODE FRAGMENTS!!!
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
    "os/exec"
    "runtime"
    "github.com/sirupsen/logrus"
    "github.com/tyler-smith/go-bip39"
    "golang.org/x/term"

    "gramium/core"
)

func CallClear() {
    var cmd *exec.Cmd
    
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd", "/c", "cls")
    } else {
        cmd = exec.Command("clear")
    }
    
    cmd.Stdout = os.Stdout
    cmd.Run()
}

func RunCLI(proxyURL string) {
    CallClear()
    fmt.Print(" ██████╗ ██████╗  █████╗ ███╗   ███╗██╗██╗   ██╗███╗   ███╗\n")
    fmt.Print("██╔════╝ ██╔══██╗██╔══██╗████╗ ████║██║██║   ██║████╗ ████║\n")
    fmt.Print("██║  ███╗██████╔╝███████║██╔████╔██║██║██║   ██║██╔████╔██║\n")
    fmt.Print("██║   ██║██╔══██╗██╔══██║██║╚██╔╝██║██║██║   ██║██║╚██╔╝██║\n")
    fmt.Print("╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║██║╚██████╔╝██║ ╚═╝ ██║\n")
    fmt.Print(" ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝\n")
    fmt.Print("\n")                                                       
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
        fmt.Println("\nWARNING! If you forget your password, username, or any other authentication details, you will not be able to recover your account!")
        fmt.Println("\nSelect an authentication method:")
        fmt.Println("  1. Master key (password)")
        fmt.Println("  2. Login + password")
        fmt.Println("  3. Seed phrase (BIP-39, 12 words)")
        fmt.Print("Your choice (1-3): ")
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
            fmt.Print("Enter a login(this can be anything, an email address, a phone number, etc): ")
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
            fmt.Print("[AUTH] Enter login(auth): ")
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
        }

        if data, err := os.ReadFile(metaFile); err == nil {
            json.Unmarshal(data, meta)
        }
    }

    CallClear()
    fmt.Print(" ██████╗ ██████╗  █████╗ ███╗   ███╗██╗██╗   ██╗███╗   ███╗\n")
    fmt.Print("██╔════╝ ██╔══██╗██╔══██╗████╗ ████║██║██║   ██║████╗ ████║\n")
    fmt.Print("██║  ███╗██████╔╝███████║██╔████╔██║██║██║   ██║██╔████╔██║\n")
    fmt.Print("██║   ██║██╔══██╗██╔══██║██║╚██╔╝██║██║██║   ██║██║╚██╔╝██║\n")
    fmt.Print("╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║██║╚██████╔╝██║ ╚═╝ ██║\n")
    fmt.Print(" ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝\n")
    fmt.Print("\n")

    cfg := &core.Config{
        Mode:     "speed",
        DBPath:   dbPath,
        ProxyURL: proxyURL,
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
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         G R A M I U M   C L I   —   Help                      ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  BASIC COMMANDS
  ───────────────
    /help                     – show this help
    /exit                     – quit the application
    /ip                       – show your public IP with detailed geolocation
                                (country, region, city, coordinates, ISP, AS, TZ)
                                If a proxy is active, the IP of the exit node is shown.

  PROFILE & SETTINGS
  ──────────────────
    /me                       – display your Gramium peer ID and all metadata
    /setmeta <key> <value>    – update a metadata field.
                                Keys: username, display_name, bio, status
                                Example: /setmeta status "away"
    /changepass               – change your master password (methods 1 and 2 only)
    /switch <mode>            – switch network mode: speed or anonymity.
                                Affects libp2p NAT, relay and hole punching.

  CONTACT MANAGEMENT
  ──────────────────
    /add <name> <id1> [id2]  – add a contact.
                                Each ID can be prefixed with:
                                  gramium:  – for libp2p Peer ID (base58)
                                  tox:      – for Tox ID (hexadecimal) – currently disabled
                                If no prefix is given, ID is assumed to be gramium.
                                Examples:
                                  /add Alice gramium:12D3KooW...
                                  /add Bob 12D3KooW...                (gramium assumed)
                                  /add Charlie gramium:... tox:...
    /list                     – show all contacts with names, statuses and IDs
    /whois <name_or_id>      – show detailed info for a contact
    /remove <name_or_id>     – delete a contact and all message history
    /debug                    – dump raw contacts table (id, username, peer_id, tox_id)

  MESSAGING
  ──────────
    /send <to> <message>      – send a message via Gramium protocol.
                                <to> can be a contact name, Peer ID, or full gramium:ID.
                                Example: /send Alice "Hello, world!"
    /history <contact> [n]    – show last n messages (default 20) with a contact

  DANGEROUS
  ──────────
    /purge                    – DELETE ALL DATA: contacts, messages, keys, encrypted DB.
                                Requires password confirmation and exits after completion.

╔═══════════════════════════════════════════════════════════════════════════════╗
║  NOTES                                                                        ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  • Gramium Peer ID is a base58 string like 12D3KooW...                        ║
║  • Tox support is currently disabled (code fragments remain).                 ║
║  • Proxy support: launch with --proxy=socks5://127.0.0.1:1080 or              ║
║    --proxy=http://proxy.example.com:8080. All network traffic (including      ║
║    /ip queries) will go through the proxy.                                    ║
║  • All metadata changes are saved to ~/.gramium/meta.json and encrypted DB.   ║
║  • Commands can be used with or without the '/' prefix (but /help requires    ║
║    the slash).                                                                ║
║  • For more details, check the source code or project documentation.          ║
╚═══════════════════════════════════════════════════════════════════════════════╝
`)

        case "/me":
            ids := node.GetIDs()
            fmt.Printf("[ID] Gramium: %s\n", ids["gramium"])

            //TOX DISABLED!!!
            //
            //if toxID, ok := ids["tox"]; ok {
            //    fmt.Printf("[TOX] Tox ID: %s\n", toxID)
            //} else {
            //    fmt.Println("[TOX] Tox is not running")
            //}
            //
            //TOX DISABLED!!!

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
                fmt.Println("[ERROR] Usage: /add <name> <id1> [id2]")
                fmt.Println("  Each id can have prefix 'gramium:' or 'tox:'")
                continue
            }
            name := fields[1]
            var peerID, toxID string        

            parseID := func(s string) (string, string) {
                if strings.HasPrefix(s, "gramium:") {
                    return strings.TrimPrefix(s, "gramium:"), "gramium"
                }
                if strings.HasPrefix(s, "tox:") {
                    return strings.TrimPrefix(s, "tox:"), "tox"
                }
                return s, "gramium"
            }       

            id1, typ1 := parseID(fields[2])
            if typ1 == "gramium" {
                peerID = id1
            } else {
                toxID = id1
            }       

            if len(fields) >= 4 {
                id2, typ2 := parseID(fields[3])
                if typ2 == "gramium" {
                    if peerID != "" {
                        fmt.Println("[WARN] Already have a gramium ID, overwriting")
                    }
                    peerID = id2
                } else {
                    if toxID != "" {
                        fmt.Println("[WARN] Already have a tox ID, overwriting")
                    }
                    toxID = id2
                }
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
            //TOX DISABLED!!!
            //
            //if len(fields) < 4 {
            //
            //TOX DISABLED!!!

            if len(fields) < 3 {
                fmt.Println("[ERROR] Usage: /send <to> <message>")
                continue
            }

            //TOX DISABLED!!!
            //
            //protocol := fields[1]
            //to := fields[2]
            //
            //TOX DISABLED!!!

            to := fields[1]

            //TOX DISABLED!!!
            //
            //message := strings.Join(fields[3:], " ")
            //
            //TOX DISABLED!!!

            message := strings.Join(fields[2:], " ")

            //TOX DISABLED!!!
            //
            //if protocol != "gramium" && protocol != "tox" {
            //    fmt.Println("[ERROR] Protocol must be gramium or tox")
            //    continue
            //}
            //if err := node.SendMessage(to, []byte(message), protocol); err != nil {
            //
            //TOX DISABLED!!!

            if err := node.SendMessage(to, []byte(message), "gramium"); err != nil {
                fmt.Printf("[ERROR] Send failed: %v\n", err)
            } else {
                //TOX DISABLED!!!
                //
                //fmt.Printf("[OK] Message sent via %s\n", protocol)
                //
                //TOX DISABLED!!!

                fmt.Println("[OK] Message sent")
            }

        case "/ip":
            info, err := node.GetIPInfo()
            if err != nil {
                fmt.Printf("[ERROR] Failed to get IP info: %v\n", err)
                continue
            }       

            locParts := []string{}
            if info.Country != "" {
                locParts = append(locParts, info.Country)
            }
            if info.CountryCode != "" {
                locParts = append(locParts, info.CountryCode)
            }
            if info.RegionName != "" {
                locParts = append(locParts, info.RegionName)
            }
            if info.Region != "" {
                locParts = append(locParts, info.Region)
            }
            if info.City != "" {
                locParts = append(locParts, info.City)
            }
            locationStr := strings.Join(locParts, "/")      

            output := fmt.Sprintf("Your IP is: %s", info.Query)
            if locationStr != "" {
                output += fmt.Sprintf(" (%s", locationStr)
                if info.Lat != 0 || info.Lon != 0 {
                    output += fmt.Sprintf(" - %.4f,%.4f", info.Lat, info.Lon)
                }
                output += ")"
            }       

            details := []string{}
            if info.Timezone != "" {
                details = append(details, fmt.Sprintf("TZ: %s", info.Timezone))
            }
            if info.Isp != "" {
                details = append(details, fmt.Sprintf("ISP: %s", info.Isp))
            }
            if info.Org != "" && info.Org != info.Isp {
                details = append(details, fmt.Sprintf("Org: %s", info.Org))
            }
            if info.As != "" {
                details = append(details, fmt.Sprintf("AS/ASN: %s", info.As))
            }
            if len(details) > 0 {
                output += " ; " + strings.Join(details, " ; ")
            }       

            if node.Cfg.ProxyURL != "" {
                output += " ; [PROXY]"
            }       

            fmt.Println("[IP]", output)

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
                fmt.Print("[AUTH] Enter login (auth): ")
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