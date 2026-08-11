//IMPORTANT NOTE: TOX SUPPPORT IS DISABLED, BUT DO NOT REMOVE THE COMMENTED CODE FRAGMENTS!!!
package core

import (
    "encoding/json"
    "io"
    "net/http"
    "context"
    "path/filepath"
    "crypto/rand"
    "database/sql"
    "fmt"
    "sync"
    "math/big"
    "strings"
    "time"
    "os"
    "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p-kad-dht"
    "github.com/libp2p/go-libp2p/core/crypto"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/p2p/security/noise"
    "github.com/libp2p/go-libp2p/p2p/transport/tcp"
)

type StatusInfo struct {
    PeerID          string
    Mode            string
    BootstrapTotal  int
    BootstrapOK     int
    BootstrapFailed int
    ConnectedAddrs  []string
    FailedAddrs     []string
    ContactsCount   int
    DHTStarted      bool
}

func (n *Node) GetStatus() *StatusInfo {
    n.bootstrapMutex.Lock()
    defer n.bootstrapMutex.Unlock()

    var okAddrs, failAddrs []string
    total := len(n.bootstrapStatus)
    okCount := 0
    for addr, connected := range n.bootstrapStatus {
        if connected {
            okAddrs = append(okAddrs, addr)
            okCount++
        } else {
            failAddrs = append(failAddrs, addr)
        }
    }

    var contacts int
    if n.DB != nil {
        _ = n.DB.QueryRow("SELECT COUNT(*) FROM contacts").Scan(&contacts)
    }

    return &StatusInfo{
        PeerID:          n.PeerID.String(),
        Mode:            n.Cfg.Mode,
        BootstrapTotal:  total,
        BootstrapOK:     okCount,
        BootstrapFailed: total - okCount,
        ConnectedAddrs:  okAddrs,
        FailedAddrs:     failAddrs,
        ContactsCount:   contacts,
        DHTStarted:      n.Dht != nil,
    }
}

type IPInfo struct {
    Status      string  `json:"status"`
    Country     string  `json:"country"`
    CountryCode string  `json:"countryCode"`
    Region      string  `json:"region"`
    RegionName  string  `json:"regionName"`
    City        string  `json:"city"`
    Zip         string  `json:"zip"`          
    Lat         float64 `json:"lat"`
    Lon         float64 `json:"lon"`
    Timezone    string  `json:"timezone"`
    Isp         string  `json:"isp"`
    Org         string  `json:"org"`
    As          string  `json:"as"`
    Query       string  `json:"query"`
}

type PeerMeta struct {
    Username      string   `json:"username"`
    DisplayName   string   `json:"display_name,omitempty"`
    Bio           string   `json:"bio,omitempty"`
    AvatarHash    string   `json:"avatar_hash,omitempty"`
    ClientName    string   `json:"client_name"`
    ClientVersion string   `json:"client_version"`
    ClientOS      string   `json:"client_os,omitempty"`
    Status        string   `json:"status"`
    Features      []string `json:"features,omitempty"`
}

type Config struct {
    Mode   string
    DBPath string
    ProxyURL string
}

type Node struct {
    ctx          context.Context
    cancel       context.CancelFunc
    Cfg          *Config
    Host         host.Host
    Dht          *dht.IpfsDHT
    DB           *sql.DB
    PeerID       peer.ID
    PrivKey      crypto.PrivKey
    PubKey       crypto.PubKey
    MyMeta       *PeerMeta
    bootstrapStatus map[string]bool
    bootstrapMutex  sync.Mutex
    //TOX DISABLED!!!
    //
    //ToxNode      *ToxNode
    //ToxCancel    context.CancelFunc
    //
    //TOX DISABLED!!!
    AuthManager  *AuthManager
    dbPath       string
}

func (n *Node) GetIPInfo() (*IPInfo, error) {
    client := &http.Client{Timeout: 10 * time.Second}
    
    resp, err := client.Get("http://ip-api.com/json")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var info IPInfo
    if err := json.Unmarshal(body, &info); err != nil {
        return nil, err
    }
    
    if info.Status != "success" {
        return nil, fmt.Errorf("API returned status: %s", info.Status)
    }
    
    return &info, nil
}

func (n *Node) ExportDecryptedDB(password string) error {
    home, err := os.UserHomeDir()
    if err != nil {
        return fmt.Errorf("failed to get home dir: %w", err)
    }
    decryptedDir := filepath.Join(home, ".gramium", "decrypted")
    outputPath := filepath.Join(decryptedDir, "gramium.db")
    return n.AuthManager.ExportDecryptedDatabase(password, outputPath)
}

func NewNode(cfg *Config, password string, meta *PeerMeta) (*Node, error) {
    ctx, cancel := context.WithCancel(context.Background())
    n := &Node{
        ctx:             ctx,
        cancel:          cancel,
        Cfg:             cfg,
        dbPath:          cfg.DBPath,
        bootstrapStatus: make(map[string]bool), 
    }

    if cfg.ProxyURL != "" {
        os.Setenv("HTTP_PROXY", cfg.ProxyURL)
        os.Setenv("HTTPS_PROXY", cfg.ProxyURL)
        if strings.HasPrefix(cfg.ProxyURL, "socks5://") {
            os.Setenv("ALL_PROXY", cfg.ProxyURL)
        }
        fmt.Println("[PROXY] Using proxy:", cfg.ProxyURL)
    }

    n.AuthManager = NewAuthManager(cfg.DBPath)

    db, loadedMeta, err := n.AuthManager.OpenDatabase(password)
    if err != nil {
        return nil, fmt.Errorf("authentication error: %w", err)
    }
    n.DB = db
    if loadedMeta != nil {
        n.MyMeta = loadedMeta
    } else {
        n.MyMeta = meta
    }

    if err := n.loadOrGenerateKeysFromDB(); err != nil {
        return nil, err
    }

    if err := n.setupHost(); err != nil {
        return nil, err
    }
    if err := n.setupDHT(); err != nil {
        return nil, err
    }
    n.Host.SetStreamHandler("/gramium/1.0.0", n.handleStream)
    
    //TOX DISABLED!!!
    //
    //toxCtx, toxCancel := context.WithCancel(ctx)
    //toxNode, err := NewToxNode(toxCtx, n.DB, n.AuthManager, n.Cfg)
    //if err != nil {
    //    fmt.Println("[WARNING] Tox not started:", err)
    //    n.ToxCancel = toxCancel
    //} else {
    //    n.ToxNode = toxNode
    //    n.ToxCancel = toxCancel
    //}
    //
    //TOX DISABLED!!!
    return n, nil
}

func (n *Node) loadOrGenerateKeysFromDB() error {
    privBytes, err := n.AuthManager.GetPrivKey()
    if err != nil {
        return fmt.Errorf("failed to read privkey from DB: %w", err)
    }

    if privBytes != nil {
        priv, err := crypto.UnmarshalPrivateKey(privBytes)
        if err != nil {
            return fmt.Errorf("failed to unmarshal privkey: %w", err)
        }
        n.PrivKey = priv
        n.PubKey = priv.GetPublic()
        n.PeerID, _ = peer.IDFromPublicKey(n.PubKey)
        return nil
    }

    priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
    if err != nil {
        return err
    }
    n.PrivKey = priv
    n.PubKey = pub
    n.PeerID, _ = peer.IDFromPublicKey(pub)

    data, err := crypto.MarshalPrivateKey(priv)
    if err != nil {
        return err
    }
    if err := n.AuthManager.SetPrivKey(data); err != nil {
        return fmt.Errorf("failed to save privkey to DB: %w", err)
    }
    return nil
}

func (n *Node) setupHost() error {
    opts := []libp2p.Option{
        libp2p.Identity(n.PrivKey),
        libp2p.ListenAddrStrings(
            "/ip4/0.0.0.0/tcp/0",
            "/ip6/::/tcp/0",
        ),
        libp2p.Security(noise.ID, noise.New),
        libp2p.Transport(tcp.NewTCPTransport),
    }
    if n.Cfg.Mode == "anonymity" {
        opts = append(opts,
            libp2p.EnableRelay(),
            libp2p.EnableAutoRelay(),
            libp2p.EnableHolePunching(),
        )
    } else {
        opts = append(opts,
            libp2p.NATPortMap(),
            libp2p.EnableHolePunching(),
        )
    }
    h, err := libp2p.New(opts...)
    if err != nil {
        return err
    }
    n.Host = h
    return nil
}

func (n *Node) LoadBootstrapPeersFromDB() ([]string, error) {
    rows, err := n.DB.Query("SELECT address FROM bootstrap_peers ORDER BY id")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var peers []string
    for rows.Next() {
        var addr string
        if err := rows.Scan(&addr); err != nil {
            return nil, err
        }
        peers = append(peers, addr)
    }
    return peers, nil
}

func (n *Node) AddBootstrapPeer(addr string) error {
    _, err := n.DB.Exec("INSERT OR IGNORE INTO bootstrap_peers (address, added_at) VALUES (?, ?)", addr, time.Now().Unix())
    return err
}

func (n *Node) RemoveBootstrapPeer(addr string) error {
    _, err := n.DB.Exec("DELETE FROM bootstrap_peers WHERE address = ?", addr)
    return err
}

func (n *Node) ListBootstrapPeers() ([]string, error) {
    return n.LoadBootstrapPeersFromDB()
}

func (n *Node) setupDHT() error {
    fmt.Print("[INFO] Connecting to bootstrap nodes, please wait...\n")
    dhtInstance, err := dht.New(n.ctx, n.Host)
    if err != nil {
        return err
    }
    n.Dht = dhtInstance

    peers, err := n.LoadBootstrapPeersFromDB()
    if err != nil {
        peers = []string{
            "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
            "/ip4/104.236.179.241/tcp/4001/p2p/QmSoLPppuBtQSGwKDZT2M73ULpjvfd3aZ6ha4oFGL1KrGM",
            "/ip4/128.199.219.111/tcp/4001/p2p/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu",
            "/ip4/104.236.76.40/tcp/4001/p2p/QmSoLV4Bbm51jM9C4gDYZQ9Cy3U6aXMJDAbzgu2fzaDs64",
            "/ip4/178.62.158.247/tcp/4001/p2p/QmSoLer265NRgSp2LA3dPaeykiS1J6DifTC88f5uVQKNAd",
            "/ip4/144.76.46.99/tcp/4001/p2p/QmSoLpPVmHKQ4XTPdz8tjDFgdeRWkpZd8ZkvWLxqR9jt2a",
            "/ip4/138.201.67.219/tcp/4001/p2p/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu",
            "/ip6/2604:a880:1:20::203:d001/tcp/4001/p2p/QmSoLPppuBtQSGwKDZT2M73ULpjvfd3aZ6ha4oFGL1KrGM",
            "/ip6/2400:6180:0:d0::151:6001/tcp/4001/p2p/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu",
            "/ip6/2604:a880:800:10::4a:5001/tcp/4001/p2p/QmSoLV4Bbm51jM9C4gDYZQ9Cy3U6aXMJDAbzgu2fzaDs64",
            "/ip6/2a03:b0c0:0:1010::23:1001/tcp/4001/p2p/QmSoLer265NRgSp2LA3dPaeykiS1J6DifTC88f5uVQKNAd",
            "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
            "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
            "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
            "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
        }
    }  

    for _, addr := range peers {
        info, err := peer.AddrInfoFromString(addr)
        if err != nil {
            n.recordBootstrapStatus(addr, false)
            continue
        }
        if err := n.Host.Connect(n.ctx, *info); err != nil {
            n.recordBootstrapStatus(addr, false)
        } else {
            n.recordBootstrapStatus(addr, true)
        }
    }
    return nil
}

func (n *Node) recordBootstrapStatus(addr string, ok bool) {
    n.bootstrapMutex.Lock()
    defer n.bootstrapMutex.Unlock()
    n.bootstrapStatus[addr] = ok
}

func (n *Node) initDB() error {
    db, err := sql.Open("sqlite", n.Cfg.DBPath)
    if err != nil {
        return err
    }
    n.DB = db
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id TEXT UNIQUE,
            tox_id TEXT UNIQUE,
            username TEXT,
            display_name TEXT,
            bio TEXT,
            avatar_hash TEXT,
            client_name TEXT,
            client_version TEXT,
            client_os TEXT,
            status TEXT,
            features TEXT,
            last_seen INTEGER,
            tox_meta_sent BOOLEAN DEFAULT 0
        );
    `)
    return err
}

func (n *Node) ResolveContact(identifier string) (string, string, error) {
    var peerIDStr, toxIDStr string
    row := n.DB.QueryRow("SELECT peer_id, tox_id FROM contacts WHERE username = ? OR peer_id = ? OR tox_id = ?", identifier, identifier, identifier)
    err := row.Scan(&peerIDStr, &toxIDStr)
    if err != nil {
        return "", "", fmt.Errorf("contact not found")
    }
    return peerIDStr, toxIDStr, nil
}

func (n *Node) sendHandshake(stream network.Stream) error {
    data, err := json.Marshal(n.MyMeta)
    if err != nil {
        return err
    }
    _, err = stream.Write(append(data, '\n'))
    return err
}

func (n *Node) readHandshake(stream network.Stream) (*PeerMeta, error) {
    buf := make([]byte, 0, 1024)
    chunk := make([]byte, 1)
    for {
        _, err := stream.Read(chunk)
        if err != nil {
            return nil, err
        }
        if chunk[0] == '\n' {
            break
        }
        buf = append(buf, chunk[0])
        if len(buf) > 4096 {
            return nil, fmt.Errorf("metadata too long")
        }
    }
    var meta PeerMeta
    err := json.Unmarshal(buf, &meta)
    return &meta, err
}

func (n *Node) updateContactMeta(peerIDStr, toxIDStr string, meta *PeerMeta) error {
    tx, err := n.DB.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()

    featuresJSON, _ := json.Marshal(meta.Features)

    var existingToxID string
    if toxIDStr == "" {
        row := tx.QueryRow("SELECT tox_id FROM contacts WHERE peer_id = ?", peerIDStr)
        row.Scan(&existingToxID)
        toxIDStr = existingToxID
    }

    var toxIDPtr interface{} = nil
    if toxIDStr != "" {
        toxIDPtr = toxIDStr
    }

    _, err = tx.Exec(`
        INSERT INTO contacts (
            peer_id, tox_id, username, display_name, bio, avatar_hash,
            client_name, client_version, client_os, status, features, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(peer_id) DO UPDATE SET
            tox_id = COALESCE(?, tox_id),
            username = excluded.username,
            display_name = excluded.display_name,
            bio = excluded.bio,
            avatar_hash = excluded.avatar_hash,
            client_name = excluded.client_name,
            client_version = excluded.client_version,
            client_os = excluded.client_os,
            status = excluded.status,
            features = excluded.features,
            last_seen = excluded.last_seen
    `, peerIDStr, toxIDPtr, meta.Username, meta.DisplayName, meta.Bio, meta.AvatarHash,
        meta.ClientName, meta.ClientVersion, meta.ClientOS, meta.Status, string(featuresJSON), time.Now().Unix(),
        toxIDPtr)
    if err != nil {
        return err
    }
    return tx.Commit()
}

func (n *Node) SendMessage(to string, data []byte, protocol string) error {
    //TOX DISABLED!!!
    //
    //if protocol == "tox" {
    //    if n.ToxNode == nil {
    //        return fmt.Errorf("Tox is not available")
    //    }
    //    return n.ToxNode.SendMessage(to, string(data), n.MyMeta)
    //}
    //
    //TOX DISABLED!!!
    return n.sendGramiumMessage(to, data)
}

func (n *Node) sendGramiumMessage(to string, data []byte) error {
    addrInfo, err := n.resolveGramiumContact(to)
    if err != nil {
        return err
    }
    stream, err := n.Host.NewStream(n.ctx, addrInfo.ID, "/gramium/1.0.0")
    if err != nil {
        return err
    }
    defer stream.Close()
    if err := n.sendHandshake(stream); err != nil {
        return err
    }
    remoteMeta, err := n.readHandshake(stream)
    if err != nil {
        return err
    }
    n.updateContactMeta(addrInfo.ID.String(), "", remoteMeta)
    if n.Cfg.Mode == "anonymity" {
        delay, _ := rand.Int(rand.Reader, big.NewInt(4500))
        time.Sleep(time.Duration(delay.Int64()+500) * time.Millisecond)
        padded := make([]byte, 1024)
        copy(padded, data)
        rand.Read(padded[len(data):])
        data = padded
    }
    _, err = stream.Write(data)
    return err
}

func trimGramiumPrefix(id string) string {
    if strings.HasPrefix(id, "gramium:") {
        return id[len("gramium:"):]
    }
    return id
}

func (n *Node) resolveGramiumContact(identifier string) (peer.AddrInfo, error) {
    cleanID := trimGramiumPrefix(identifier)
    var peerIDStr string
    row := n.DB.QueryRow("SELECT peer_id FROM contacts WHERE username = ? OR peer_id = ?", cleanID, cleanID)
    err := row.Scan(&peerIDStr)
    if err != nil {
        pid, err := peer.Decode(cleanID)
        if err == nil {
            return n.Dht.FindPeer(n.ctx, pid)
        }
        return peer.AddrInfo{}, fmt.Errorf("contact not found: %v", err)
    }
    if peerIDStr == "" {
        pid, err := peer.Decode(cleanID)
        if err == nil {
            return n.Dht.FindPeer(n.ctx, pid)
        }
        return peer.AddrInfo{}, fmt.Errorf("contact has empty peer_id and identifier is not a valid peer ID")
    }
    pid, err := peer.Decode(peerIDStr)
    if err != nil {
        return peer.AddrInfo{}, err
    }
    return n.Dht.FindPeer(n.ctx, pid)
}

func (n *Node) DebugContacts() ([]string, error) {
    rows, err := n.DB.Query("SELECT id, username, peer_id, tox_id FROM contacts")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var lines []string
    for rows.Next() {
        var id int
        var username, peerID, toxID sql.NullString
        rows.Scan(&id, &username, &peerID, &toxID)
        lines = append(lines, fmt.Sprintf("ID:%d username:%s peer_id:%s tox_id:%s", id, username.String, peerID.String, toxID.String))
    }
    return lines, nil
}

func (n *Node) handleStream(stream network.Stream) {
    defer stream.Close()
    sec := stream.Conn().ConnState().Security
    fmt.Printf("[SECURE] Encrypted: %s\n", sec)
    remoteMeta, err := n.readHandshake(stream)
    if err != nil {
        fmt.Println("[ERROR] Failed to read metadata:", err)
        return
    }
    if err := n.sendHandshake(stream); err != nil {
        fmt.Println("[ERROR] Failed to send metadata:", err)
        return
    }
    peerIDStr := stream.Conn().RemotePeer().String()
    n.updateContactMeta(peerIDStr, "", remoteMeta)
    buf := make([]byte, 1024)
    readLen, err := stream.Read(buf)
    if err != nil {
        return
    }
    msg := string(buf[:readLen])
    displayName := remoteMeta.Username
    if remoteMeta.DisplayName != "" {
        displayName = remoteMeta.DisplayName
    }
    fmt.Printf("\n[MESSAGE] [%s] %s\n", displayName, msg)
    tx, err := n.DB.Begin()
    if err != nil {
        fmt.Println("Transaction start error:", err)
        return
    }
    defer tx.Rollback()
    var contactID int
    row := tx.QueryRow("SELECT id FROM contacts WHERE peer_id = ?", peerIDStr)
    row.Scan(&contactID)
    if contactID > 0 {
        _, err = tx.Exec("INSERT INTO messages (contact_id, is_outgoing, message, timestamp, protocol) VALUES (?, ?, ?, ?, ?)", contactID, false, msg, time.Now().Unix(), "gramium")
        if err != nil {
            fmt.Println("Failed to save message:", err)
            return
        }
    }
    tx.Commit()
}

func (n *Node) SaveMyMeta(meta *PeerMeta) error {
    if n.DB == nil {
        return fmt.Errorf("database is not open")
    }
    featuresJSON, _ := json.Marshal(meta.Features)
    _, err := n.DB.Exec(`
        UPDATE auth SET 
            username = ?,
            display_name = ?,
            bio = ?,
            avatar_hash = ?,
            status = ?,
            features = ?
        WHERE id = 1
    `, meta.Username, meta.DisplayName, meta.Bio, meta.AvatarHash, meta.Status, string(featuresJSON))
    return err
}

func (n *Node) GetPeerID() string {
    return n.PeerID.String()
}

func (n *Node) GetMyMeta() *PeerMeta {
    return n.MyMeta
}

func (n *Node) SetMyMeta(meta *PeerMeta) {
    n.MyMeta = meta
}

func (n *Node) GetIDs() map[string]string {
    ids := make(map[string]string)
    ids["gramium"] = "gramium:" + n.PeerID.String()
    //TOX DISABLED!!!
    //
    //if n.ToxNode != nil {
    //    ids["tox"] = n.ToxNode.GetToxID()
    //}
    //
    //TOX DISABLED!!!
    return ids
}

func (n *Node) AddContact(name, peerID, toxID string) error {
    if peerID != "" {
        peerID = trimGramiumPrefix(peerID)
    }

    var peerIDPtr interface{} = nil
    if peerID != "" {
        peerIDPtr = peerID
    }
    var toxIDPtr interface{} = nil
    if toxID != "" {
        toxIDPtr = toxID
    }

    tx, err := n.DB.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()

    _, err = tx.Exec("INSERT OR IGNORE INTO contacts (peer_id, tox_id) VALUES (?, ?)", peerIDPtr, toxIDPtr)
    if err != nil {
        return err
    }

    if name != "" {
        if peerID != "" {
            _, err = tx.Exec("UPDATE contacts SET username = ? WHERE peer_id = ?", name, peerID)
        } else if toxID != "" {
            _, err = tx.Exec("UPDATE contacts SET username = ? WHERE tox_id = ?", name, toxID)
        } else {
            return fmt.Errorf("both peer_id and tox_id are empty")
        }
        if err != nil {
            return err
        }
    }

    return tx.Commit()
}

func (n *Node) ListContacts() ([]string, error) {
    rows, err := n.DB.Query("SELECT username, display_name, status, peer_id, tox_id FROM contacts")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var list []string
    for rows.Next() {
        var username, displayName, status sql.NullString
        var peerID, toxID sql.NullString

        err := rows.Scan(&username, &displayName, &status, &peerID, &toxID)
        if err != nil {
            return nil, err
        }

        name := username.String
        if !username.Valid || username.String == "" {
            name = "unnamed"
        }
        if displayName.Valid && displayName.String != "" {
            name = displayName.String + " (" + username.String + ")"
        }

        stat := status.String
        if !status.Valid || status.String == "" {
            stat = "unknown"
        }

        var id string
        if peerID.Valid && peerID.String != "" {
            id = "gramium:" + peerID.String
        }
        if toxID.Valid && toxID.String != "" {
            if id != "" {
                id += ", tox:" + toxID.String
            } else {
                id = "tox:" + toxID.String
            }
        }
        if id == "" {
            id = "no ID"
        }

        list = append(list, fmt.Sprintf("%s [%s] (%s)", name, stat, id))
    }
    return list, nil
}

func (n *Node) GetContactMeta(identifier string) (*PeerMeta, error) {
    var username, displayName, bio, avatarHash, clientName, clientVersion, clientOS, status sql.NullString
    var featuresStr sql.NullString

    row := n.DB.QueryRow(`
        SELECT username, display_name, bio, avatar_hash, client_name, client_version, client_os, status, features
        FROM contacts WHERE username = ? OR peer_id = ? OR tox_id = ?
    `, identifier, identifier, identifier)

    err := row.Scan(&username, &displayName, &bio, &avatarHash, &clientName, &clientVersion, &clientOS, &status, &featuresStr)
    if err != nil {
        return nil, err
    }

    meta := &PeerMeta{
        Username:      username.String,
        DisplayName:   displayName.String,
        Bio:           bio.String,
        AvatarHash:    avatarHash.String,
        ClientName:    clientName.String,
        ClientVersion: clientVersion.String,
        ClientOS:      clientOS.String,
        Status:        status.String,
    }
    if featuresStr.Valid && featuresStr.String != "" {
        json.Unmarshal([]byte(featuresStr.String), &meta.Features)
    }
    return meta, nil
}

func (n *Node) SwitchMode(newMode string) error {
    if newMode == n.Cfg.Mode {
        return nil
    }
    if n.Host != nil {
        n.Host.Close()
    }
    if n.Dht != nil {
        n.Dht.Close()
    }
    n.Cfg.Mode = newMode
    if err := n.setupHost(); err != nil {
        return err
    }
    if err := n.setupDHT(); err != nil {
        return err
    }
    n.Host.SetStreamHandler("/gramium/1.0.0", n.handleStream)
    return nil
}

func (n *Node) Start() error {
    fmt.Println("[START] Mode:", n.Cfg.Mode)
    ids := n.GetIDs()
    fmt.Println("[ID] Gramium ID:", ids["gramium"])
    if toxID, ok := ids["tox"]; ok {
        fmt.Println("[TOX] Tox ID:", toxID)
    }
    if n.MyMeta != nil {
        fmt.Println("[USER] Username:", n.MyMeta.Username)
    }
    return nil
}

func (n *Node) Stop() {
    n.cancel()

    //TOX DISABLED!!!
    //
    //if n.ToxNode != nil {
    //    n.ToxNode.Stop()
    //}
    //if n.ToxCancel != nil {
    //   n.ToxCancel()
    //}
    //
    //TOX DISABLED!!!

    if n.Host != nil {
        n.Host.Close()
    }
    if n.AuthManager != nil {
        if err := n.AuthManager.CloseDatabase(); err != nil {
            fmt.Println("[WARNING] Error closing database:", err)
        }
    }
}