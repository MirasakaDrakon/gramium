package core

import (
    "context"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "github.com/opd-ai/toxcore"
    "github.com/opd-ai/toxcore/crypto"
)

type ToxNodeResponse struct {
    LastScan    int64          `json:"last_scan"`
    LastRefresh int64          `json:"last_refresh"`
    Nodes       []BootstrapNode `json:"nodes"`
}

type BootstrapNode struct {
    IPv4       string `json:"ipv4"`
    IPv6       string `json:"ipv6"`
    Port       int    `json:"port"`
    TCPPorts   []int  `json:"tcp_ports"`
    PublicKey  string `json:"public_key"`
    Maintainer string `json:"maintainer"`
    Location   string `json:"location"`
    StatusUDP  bool   `json:"status_udp"`
    StatusTCP  bool   `json:"status_tcp"`
    Version    string `json:"version"`
    Motd       string `json:"motd"`
    LastPing   int64  `json:"last_ping"`
}

func FetchBootstrapNodes() []BootstrapNode {
    nodes, err := fetchFromNetwork()
    if err == nil && len(nodes) > 0 {
        fmt.Println("[OK] Loaded actual bootstrap nodes:", len(nodes))
        if len(nodes) > 10 {
            nodes = nodes[:10]
        }
        return nodes
    }
    fmt.Println("[WARNING] Failed to load node list, using fallback")
    return getFallbackNodes()
}

func fetchFromNetwork() ([]BootstrapNode, error) {
    client := http.Client{Timeout: 10 * time.Second}
    resp, err := client.Get("https://nodes.tox.chat/json")
    if err != nil {
        return nil, fmt.Errorf("HTTP request error: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status: %s", resp.Status)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("error reading response body: %w", err)
    }

    var response ToxNodeResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("JSON parse error: %w", err)
    }

    var activeNodes []BootstrapNode
    for _, node := range response.Nodes {
        if node.StatusUDP && node.IPv4 != "" && node.IPv4 != "NONE" {
            activeNodes = append(activeNodes, node)
        }
    }

    if len(activeNodes) == 0 {
        return nil, fmt.Errorf("no active UDP nodes found")
    }
    return activeNodes, nil
}

func getFallbackNodes() []BootstrapNode {
    return []BootstrapNode{
        {IPv4: "144.217.167.73", Port: 33445, PublicKey: "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C"},
        {IPv4: "3.0.24.15", Port: 33445, PublicKey: "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D"},
        {IPv4: "139.162.110.188", Port: 33445, PublicKey: "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55"},
        {IPv4: "144.172.88.203", Port: 33445, PublicKey: "2016A0F2797EE3A8B004BA623F11AAFC8146F1B8F45107232A1A1AECCE856674"},
        {IPv4: "91.146.66.26", Port: 33445, PublicKey: "B5E7DAC610DBDE55F359C7F8690B294C8E4FCEC4385DE9525DBFA5523EAD9D53"},
        {IPv4: "172.104.215.182", Port: 33445, PublicKey: "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239"},
        {IPv4: "188.214.122.30", Port: 33445, PublicKey: "2A9F7A620581D5D1B09B004624559211C5ED3D1D712E8066ACDB0896A7335705"},
        {IPv4: "43.198.227.166", Port: 33445, PublicKey: "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E"},
        {IPv4: "95.181.230.108", Port: 33445, PublicKey: "B5FFECB4E4C26409EBB88DB35793E7B39BFA3BA12AC04C096950CB842E3E130A"},
        {IPv4: "188.245.84.166", Port: 33445, PublicKey: "96B66D300BA2B59B98FC42DB1325E7092388F0379593E680ABDBEA03B9C9CE03"},
    }
}

type ToxNode struct {
    tox         *toxcore.Tox
    ctx         context.Context
    cancel      context.CancelFunc
    db          *sql.DB
    authManager *AuthManager
}

func NewToxNode(ctx context.Context, db *sql.DB, authManager *AuthManager) (*ToxNode, error) {
    ctx, cancel := context.WithCancel(ctx)
    tn := &ToxNode{ctx: ctx, cancel: cancel, db: db, authManager: authManager}

    toxKey, err := tn.authManager.GetToxKey()
    if err != nil {
        cancel()
        return nil, fmt.Errorf("error reading tox_key from DB: %w", err)
    }

    var keyData *[32]byte
    if toxKey != nil && len(toxKey) == 32 {
        var key [32]byte
        copy(key[:], toxKey)
        keyData = &key
        fmt.Println("[KEY] Tox key loaded from DB")
    } else {
        kp, err := crypto.GenerateKeyPair()
        if err != nil {
            cancel()
            return nil, fmt.Errorf("error generating Tox key: %w", err)
        }
        key := kp.Private
        keyData = &key
        if err := tn.authManager.SetToxKey(key[:]); err != nil {
            cancel()
            return nil, fmt.Errorf("error saving Tox key to DB: %w", err)
        }
        fmt.Println("[KEY] New Tox key generated and saved to DB")
    }

    opts := toxcore.NewOptions()
    opts.UDPEnabled = true
    opts.IPv6Enabled = true
    opts.MinBootstrapNodes = 1
    opts.BootstrapTimeout = 15 * time.Second

    toxSave, err := tn.authManager.GetToxSave()
    if err != nil {
        cancel()
        return nil, fmt.Errorf("error reading tox_save from DB: %w", err)
    }

    if toxSave != nil && len(toxSave) > 0 {
        opts.SavedataType = toxcore.SaveDataTypeToxSave
        opts.SavedataData = toxSave
        fmt.Println("[UNLOCK] Loaded saved Tox state from DB")
    } else {
        opts.SavedataType = toxcore.SaveDataTypeSecretKey
        opts.SavedataData = keyData[:]
    }

    tox, err := toxcore.New(opts)
    if err != nil {
        cancel()
        return nil, fmt.Errorf("error creating Tox: %w", err)
    }
    tn.tox = tox

    if toxSave == nil || len(toxSave) == 0 {
        time.Sleep(100 * time.Millisecond)
        newSave := tox.GetSavedata()
        if len(newSave) > 0 {
            if err := tn.authManager.SetToxSave(newSave); err != nil {
                fmt.Printf("[WARNING] Failed to save initial Tox state: %v\n", err)
            } else {
                fmt.Println("[SAVE] Initial Tox state saved to DB")
            }
        }
    }

    tn.registerHandlers()
    tn.bootstrap()
    go tn.loop()
    return tn, nil
}

func (tn *ToxNode) bootstrap() {
    nodes := FetchBootstrapNodes()
    for i, n := range nodes {
        if n.IPv4 == "" || n.IPv4 == "NONE" {
            continue
        }
        if i > 0 {
            time.Sleep(500 * time.Millisecond)
        }
        if err := tn.tox.Bootstrap(n.IPv4, uint16(n.Port), n.PublicKey); err != nil {
            fmt.Printf("[WARNING] Failed to connect to bootstrap node %s: %v\n", n.IPv4, err)
        } else {
            fmt.Printf("[NETWORK] Connected to bootstrap node %s:%d\n", n.IPv4, n.Port)
        }
    }
}

func (tn *ToxNode) registerHandlers() {
    tn.tox.OnFriendMessage(func(friendID uint32, message string) {
        pubKey, err := tn.tox.GetFriendPublicKey(friendID)
        if err != nil {
            fmt.Println("[WARNING] Failed to get friend public key:", err)
            return
        }
        toxID := hex.EncodeToString(pubKey[:])

        var meta PeerMeta
        if err := json.Unmarshal([]byte(message), &meta); err == nil && meta.Username != "" {
            if err := tn.saveContactMeta(toxID, &meta); err != nil {
                fmt.Println("[ERROR] Error saving metadata:", err)
            } else {
                fmt.Printf("[RECEIVE] Received metadata from %s (Tox ID: %s)\n", meta.Username, toxID)
                tn.db.Exec("UPDATE contacts SET tox_meta_sent = 1 WHERE tox_id = ?", toxID)
            }
            return
        }

        contactMeta, _ := tn.getContactMetaByToxID(toxID)
        displayName := toxID
        if contactMeta != nil && contactMeta.Username != "" {
            displayName = contactMeta.Username
        }
        fmt.Printf("\n[MESSAGE] [Tox] %s: %s\n", displayName, message)

        var contactID int
        row := tn.db.QueryRow("SELECT id FROM contacts WHERE tox_id = ?", toxID)
        row.Scan(&contactID)
        if contactID > 0 {
            tx, err := tn.db.Begin()
            if err != nil {
                fmt.Println("Transaction begin error:", err)
                return
            }
            defer tx.Rollback()
            _, err = tx.Exec("INSERT INTO messages (contact_id, is_outgoing, message, timestamp, protocol) VALUES (?, ?, ?, ?, ?)",
                contactID, false, message, time.Now().Unix(), "tox")
            if err != nil {
                fmt.Println("Error saving message:", err)
                return
            }
            tx.Commit()
        }
    })

    tn.tox.OnFriendRequest(func(publicKey [32]byte, message string) {
        fmt.Printf("[REQUEST] [Tox] Request from %x: %s\n", publicKey, message)
        friendID, err := tn.tox.AddFriendByPublicKey(publicKey)
        if err == nil {
            fmt.Println("[OK] Request accepted, friendID:", friendID)
            toxID := hex.EncodeToString(publicKey[:])
            tn.db.Exec("INSERT OR IGNORE INTO contacts (tox_id, friend_id) VALUES (?, ?)", toxID, friendID)
        } else {
            fmt.Println("[ERROR] Error accepting request:", err)
        }
    })

    tn.tox.OnConnectionStatus(func(status toxcore.ConnectionStatus) {
        fmt.Printf("[STATUS] Tox connection status: %s\n", fmt.Sprint(status))
    })
}

func (tn *ToxNode) saveContactMeta(toxID string, meta *PeerMeta) error {
    tx, err := tn.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()

    featuresJSON, _ := json.Marshal(meta.Features)
    _, err = tx.Exec(`
        INSERT INTO contacts (tox_id, username, display_name, bio, avatar_hash,
            client_name, client_version, client_os, status, features, last_seen, tox_meta_sent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(tox_id) DO UPDATE SET
            username = excluded.username,
            display_name = excluded.display_name,
            bio = excluded.bio,
            avatar_hash = excluded.avatar_hash,
            client_name = excluded.client_name,
            client_version = excluded.client_version,
            client_os = excluded.client_os,
            status = excluded.status,
            features = excluded.features,
            last_seen = excluded.last_seen,
            tox_meta_sent = 1
    `, toxID, meta.Username, meta.DisplayName, meta.Bio, meta.AvatarHash,
        meta.ClientName, meta.ClientVersion, meta.ClientOS, meta.Status, string(featuresJSON), time.Now().Unix())
    if err != nil {
        return err
    }
    return tx.Commit()
}

func (tn *ToxNode) getContactMetaByToxID(toxID string) (*PeerMeta, error) {
    var username, displayName, bio, avatarHash, clientName, clientVersion, clientOS, status, featuresStr string
    row := tn.db.QueryRow(`
        SELECT username, display_name, bio, avatar_hash, client_name, client_version, client_os, status, features
        FROM contacts WHERE tox_id = ?
    `, toxID)
    err := row.Scan(&username, &displayName, &bio, &avatarHash, &clientName, &clientVersion, &clientOS, &status, &featuresStr)
    if err != nil {
        return nil, err
    }
    var features []string
    json.Unmarshal([]byte(featuresStr), &features)
    return &PeerMeta{
        Username:      username,
        DisplayName:   displayName,
        Bio:           bio,
        AvatarHash:    avatarHash,
        ClientName:    clientName,
        ClientVersion: clientVersion,
        ClientOS:      clientOS,
        Status:        status,
        Features:      features,
    }, nil
}

func (tn *ToxNode) loop() {
    ticker := time.NewTicker(tn.tox.IterationInterval())
    defer ticker.Stop()
    for {
        select {
        case <-tn.ctx.Done():
            tn.tox.Kill()
            return
        case <-ticker.C:
            tn.tox.Iterate()
        }
    }
}

func (tn *ToxNode) GetToxID() string {
    return tn.tox.SelfGetAddress()
}

func (tn *ToxNode) SendMessage(toToxID string, message string, myMeta *PeerMeta) error {
    friendID, err := tn.ensureFriend(toToxID)
    if err != nil {
        return err
    }

    var metaSent bool
    row := tn.db.QueryRow("SELECT tox_meta_sent FROM contacts WHERE tox_id = ?", toToxID)
    row.Scan(&metaSent)

    if !metaSent {
        metaJSON, err := json.Marshal(myMeta)
        if err != nil {
            return err
        }
        if err := tn.tox.SendFriendMessage(friendID, string(metaJSON)); err != nil {
            return fmt.Errorf("failed to send metadata: %w", err)
        }
        tn.db.Exec("UPDATE contacts SET tox_meta_sent = 1 WHERE tox_id = ?", toToxID)
    }

    const maxToxMsgLen = 1300
    if len(message) > maxToxMsgLen {
        parts := splitString(message, maxToxMsgLen)
        for i, part := range parts {
            msg := fmt.Sprintf("[%d/%d] %s", i+1, len(parts), part)
            if err := tn.tox.SendFriendMessage(friendID, msg); err != nil {
                return err
            }
        }
        return nil
    }
    return tn.tox.SendFriendMessage(friendID, message)
}

func splitString(s string, chunkSize int) []string {
    var parts []string
    for len(s) > chunkSize {
        parts = append(parts, s[:chunkSize])
        s = s[chunkSize:]
    }
    if len(s) > 0 {
        parts = append(parts, s)
    }
    return parts
}

func (tn *ToxNode) ensureFriend(toToxID string) (uint32, error) {
    var friendID uint32
    row := tn.db.QueryRow("SELECT friend_id FROM contacts WHERE tox_id = ?", toToxID)
    err := row.Scan(&friendID)
    if err == nil {
        if _, err := tn.tox.GetFriendPublicKey(friendID); err == nil {
            return friendID, nil
        }
        tn.db.Exec("DELETE FROM contacts WHERE tox_id = ?", toToxID)
    }

    friendID, err = tn.tox.AddFriend(toToxID, "Hello from Gramium!")
    if err != nil {
        return 0, fmt.Errorf("error adding friend: %w", err)
    }
    _, err = tn.db.Exec("INSERT INTO contacts (tox_id, friend_id) VALUES (?, ?)", toToxID, friendID)
    if err != nil {
        return 0, fmt.Errorf("error saving contact: %w", err)
    }
    return friendID, nil
}

func (tn *ToxNode) Stop() {
    tn.cancel()
    if tn.tox != nil {
        saveData := tn.tox.GetSavedata()
        if len(saveData) > 0 {
            if err := tn.authManager.SetToxSave(saveData); err != nil {
                fmt.Printf("[WARNING] Error saving Tox state: %v\n", err)
            } else {
                fmt.Println("[SAVE] Tox state saved to DB")
            }
        }
        tn.tox.Kill()
    }
}