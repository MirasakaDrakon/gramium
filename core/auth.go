//IMPORTANT NOTE: TOX SUPPPORT IS DISABLED, BUT DO NOT REMOVE THE COMMENTED CODE FRAGMENTS!!!
package core

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "database/sql"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"

    "golang.org/x/crypto/argon2"
    _ "modernc.org/sqlite"
)

type AuthConfig struct {
    SaltLength int
    KeyLength  int
    Time       uint32
    Memory     uint32
    Threads    uint8
}

func DefaultAuthConfig() AuthConfig {
    return AuthConfig{
        SaltLength: 16,
        KeyLength:  32,
        Time:       2,
        Memory:     64 * 1024,
        Threads:    4,
    }
}

type AuthManager struct {
    config   AuthConfig
    dbPath   string
    tempPath string
    password string
    db       *sql.DB
    privKey  []byte

    //TOX DISABLED!!!
    //
    //toxKey   []byte
    //toxSave  []byte
    //
    //TOX DISABLED!!!
}

func NewAuthManager(dbPath string) *AuthManager {
    return &AuthManager{
        config:   DefaultAuthConfig(),
        dbPath:   dbPath,
        tempPath: "",
        password: "",
        db:       nil,
    }
}

type AuthMeta struct {
    Method int `json:"method"`
}

const authMetaSuffix = ".meta"

func (am *AuthManager) SaveAuthMeta(method int) error {
    meta := AuthMeta{Method: method}
    data, err := json.Marshal(meta)
    if err != nil {
        return err
    }
    return os.WriteFile(am.dbPath+authMetaSuffix, data, 0600)
}

func (am *AuthManager) LoadAuthMeta() (int, error) {
    data, err := os.ReadFile(am.dbPath + authMetaSuffix)
    if err != nil {
        return 0, err
    }
    var meta AuthMeta
    if err := json.Unmarshal(data, &meta); err != nil {
        return 0, err
    }
    return meta.Method, nil
}

func (am *AuthManager) AuthMetaExists() bool {
    _, err := os.Stat(am.dbPath + authMetaSuffix)
    return err == nil
}

func (am *AuthManager) generateSalt() ([]byte, error) {
    salt := make([]byte, am.config.SaltLength)
    _, err := rand.Read(salt)
    return salt, err
}

func (am *AuthManager) deriveKey(password string, salt []byte) []byte {
    return argon2.IDKey(
        []byte(password),
        salt,
        am.config.Time,
        am.config.Memory,
        am.config.Threads,
        uint32(am.config.KeyLength),
    )
}

func (am *AuthManager) encryptFile(srcPath, dstPath string, password string) error {
    plaintext, err := os.ReadFile(srcPath)
    if err != nil {
        return err
    }

    salt, err := am.generateSalt()
    if err != nil {
        return err
    }

    key := am.deriveKey(password, salt)
    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

    out := make([]byte, len(salt)+len(ciphertext))
    copy(out[:len(salt)], salt)
    copy(out[len(salt):], ciphertext)

    return os.WriteFile(dstPath, out, 0600)
}

func (am *AuthManager) decryptFile(srcPath, dstPath string, password string) error {
    data, err := os.ReadFile(srcPath)
    if err != nil {
        return err
    }
    if len(data) < am.config.SaltLength {
        return fmt.Errorf("file corrupted")
    }
    salt := data[:am.config.SaltLength]
    ciphertextWithNonce := data[am.config.SaltLength:]

    key := am.deriveKey(password, salt)
    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }
    nonceSize := gcm.NonceSize()
    if len(ciphertextWithNonce) < nonceSize {
        return fmt.Errorf("file corrupted")
    }
    nonce := ciphertextWithNonce[:nonceSize]
    ciphertext := ciphertextWithNonce[nonceSize:]

    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return fmt.Errorf("invalid password or corrupted file")
    }
    return os.WriteFile(dstPath, plaintext, 0600)
}

func (am *AuthManager) CreateDatabase(password string, meta *PeerMeta, method int) error {
    if err := am.SaveAuthMeta(method); err != nil {
        return fmt.Errorf("failed to save meta file: %w", err)
    }
    tempFile, err := os.CreateTemp("", "gramium_*.db")
    if err != nil {
        return fmt.Errorf("failed to create temporary file: %w", err)
    }
    tempPath := tempFile.Name()
    tempFile.Close()
    defer os.Remove(tempPath)

    db, err := sql.Open("sqlite", tempPath)
    if err != nil {
        return fmt.Errorf("failed to open temporary database: %w", err)
    }
    defer db.Close()
    //TOX DISABLED!!!
    //
    //THOSE COLONS DELETED:
    //tox_key BLOB
    //tox_save BLOB
    //
    //TOX DISABLED!!!

    _, err = db.Exec(`
        CREATE TABLE auth (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            display_name TEXT,
            bio TEXT,
            avatar_hash TEXT,
            client_name TEXT,
            client_version TEXT,
            client_os TEXT,
            status TEXT,
            features TEXT,
            created_at INTEGER,
            privkey BLOB
        );
        CREATE TABLE contacts (
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
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER,
            is_outgoing BOOLEAN,
            message TEXT,
            timestamp INTEGER,
            protocol TEXT,
            FOREIGN KEY(contact_id) REFERENCES contacts(id)
        );
        CREATE TABLE bootstrap_peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE,
            added_at INTEGER
        );
    `)

    defaultPeers := []string{
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
    for _, addr := range defaultPeers {
        _, err = db.Exec("INSERT OR IGNORE INTO bootstrap_peers (address, added_at) VALUES (?, ?)", addr, time.Now().Unix())
        if err != nil {
            fmt.Println("[WARN] Failed to insert default bootstrap peer:", err)
        }
    }
    if err != nil {
        return fmt.Errorf("failed to create tables: %w", err)
    }

    featuresJSON, _ := json.Marshal(meta.Features)
    _, err = db.Exec(`
        INSERT INTO auth (username, display_name, bio, avatar_hash, client_name, client_version, client_os, status, features, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, meta.Username, meta.DisplayName, meta.Bio, meta.AvatarHash,
        meta.ClientName, meta.ClientVersion, meta.ClientOS, meta.Status, string(featuresJSON), time.Now().Unix())
    if err != nil {
        return fmt.Errorf("failed to save metadata: %w", err)
    }

    db.Close()

    err = am.encryptFile(tempPath, am.dbPath, password)
    if err != nil {
        return fmt.Errorf("failed to encrypt database: %w", err)
    }

    fmt.Println("[OK] Database created and encrypted")
    return nil
}

func (am *AuthManager) ExportDecryptedDatabase(password string, outputPath string) error {
    if _, err := os.Stat(am.dbPath); os.IsNotExist(err) {
        return fmt.Errorf("database not found: %s", am.dbPath)
    }

    dir := filepath.Dir(outputPath)
    if err := os.MkdirAll(dir, 0700); err != nil {
        return fmt.Errorf("failed to create output directory: %w", err)
    }

    err := am.decryptFile(am.dbPath, outputPath, password)
    if err != nil {
        return fmt.Errorf("failed to decrypt database: %w", err)
    }

    return nil
}

func (am *AuthManager) PurgeDatabase(password string) error {
    if _, err := os.Stat(am.dbPath); os.IsNotExist(err) {
        return fmt.Errorf("database not found")
    }

    tempFile, err := os.CreateTemp("", "gramium_purge_check_*.db")
    if err != nil {
        return fmt.Errorf("failed to create temporary file: %w", err)
    }
    tempPath := tempFile.Name()
    tempFile.Close()
    defer os.Remove(tempPath)

    if err := am.decryptFile(am.dbPath, tempPath, password); err != nil {
        return fmt.Errorf("invalid password: %w", err)
    }

    filesToRemove := []string{
        am.dbPath,
        am.dbPath + ".enc",
        am.tempPath,
        filepath.Join(filepath.Dir(am.dbPath), "meta.json"),
        filepath.Join(filepath.Dir(am.dbPath), "gramium.log"),
    }

    var removeErr error
    for _, f := range filesToRemove {
        if _, err := os.Stat(f); err == nil {
            if err := os.Remove(f); err != nil {
                removeErr = fmt.Errorf("failed to delete %s: %w", f, err)
            }
        }
    }

    am.db = nil
    am.tempPath = ""
    am.password = ""
    am.privKey = nil

    //TOX DISABLED!!!
    //
    //am.toxKey = nil
    //am.toxSave = nil
    //
    //TOX DISABLED!!!

    if removeErr != nil {
        return fmt.Errorf("partial removal: %w", removeErr)
    }

    return nil
}

func (am *AuthManager) OpenDatabase(password string) (*sql.DB, *PeerMeta, error) {
    if _, err := os.Stat(am.dbPath); os.IsNotExist(err) {
        return nil, nil, fmt.Errorf("database not found: %s", am.dbPath)
    }

    tempFile, err := os.CreateTemp("", "gramium_decrypted_*.db")
    if err != nil {
        return nil, nil, fmt.Errorf("failed to create temporary file: %w", err)
    }
    am.tempPath = tempFile.Name()
    tempFile.Close()

    err = am.decryptFile(am.dbPath, am.tempPath, password)
    if err != nil {
        os.Remove(am.tempPath)
        am.tempPath = ""
        return nil, nil, fmt.Errorf("failed to decrypt database: %w", err)
    }

    db, err := sql.Open("sqlite", am.tempPath)
    if err != nil {
        os.Remove(am.tempPath)
        am.tempPath = ""
        return nil, nil, fmt.Errorf("failed to open temporary database: %w", err)
    }

    var count int
    err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='auth'").Scan(&count)
    if err != nil || count == 0 {
        db.Close()
        os.Remove(am.tempPath)
        am.tempPath = ""
        return nil, nil, fmt.Errorf("corrupted database or invalid password")
    }

    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS bootstrap_peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE,
            added_at INTEGER
        );
    `)
    if err != nil {
        fmt.Println("[WARN] Could not ensure bootstrap_peers table:", err)
    }

    var username, displayName, bio, avatarHash, clientName, clientVersion, clientOS, status, featuresStr string
    var createdAt int64

    //TOX DISABLED!!!
    //
    //var privKey, toxKey, toxSave []byte
    //
    //TOX DISABLED!!!
    
    var privKey []byte
    err = db.QueryRow(`
        SELECT username, display_name, bio, avatar_hash, client_name, client_version, client_os, status, features, created_at,
               privkey
        FROM auth LIMIT 1
    `).Scan(&username, &displayName, &bio, &avatarHash,
        &clientName, &clientVersion, &clientOS, &status, &featuresStr, &createdAt,
        &privKey) //&toxKey, &toxSave(362) AND tox_key, tox_save(358) DELETED
    if err != nil {
        db.Close()
        os.Remove(am.tempPath)
        am.tempPath = ""
        return nil, nil, fmt.Errorf("failed to read metadata: %w", err)
    }

    meta := &PeerMeta{
        Username:      username,
        DisplayName:   displayName,
        Bio:           bio,
        AvatarHash:    avatarHash,
        ClientName:    clientName,
        ClientVersion: clientVersion,
        ClientOS:      clientOS,
        Status:        status,
    }
    if featuresStr != "" {
        json.Unmarshal([]byte(featuresStr), &meta.Features)
    }

    am.privKey = privKey

    //TOX DISABLED!!!
    //am.toxKey = toxKey
    //am.toxSave = toxSave
    //TOX DISABLED!!!

    am.password = password
    am.db = db

    fmt.Println("[OK] Database opened and decrypted")
    return db, meta, nil
}

func (am *AuthManager) CloseDatabase() error {
    if am.db == nil {
        return nil
    }
    if am.tempPath == "" {
        return nil
    }
    if am.password == "" {
        return fmt.Errorf("password not saved, cannot encrypt database")
    }

    if err := am.db.Close(); err != nil {
        return fmt.Errorf("failed to close database: %w", err)
    }
    am.db = nil

    if _, err := os.Stat(am.tempPath); os.IsNotExist(err) {
        am.tempPath = ""
        return nil
    }

    err := am.encryptFile(am.tempPath, am.dbPath, am.password)
    if err != nil {
        return fmt.Errorf("failed to encrypt database on close: %w", err)
    }

    if err := os.Remove(am.tempPath); err != nil {
        return fmt.Errorf("failed to remove temporary file: %w", err)
    }
    am.tempPath = ""
    am.password = ""

    fmt.Println("[OK] Database encrypted and saved")
    return nil
}

func (am *AuthManager) GetPrivKey() ([]byte, error) {
    if am.db == nil {
        return nil, fmt.Errorf("database is not open")
    }
    if am.privKey == nil {
        return nil, nil
    }
    return am.privKey, nil
}

func (am *AuthManager) SetPrivKey(data []byte) error {
    if am.db == nil {
        return fmt.Errorf("database is not open")
    }
    am.privKey = data
    _, err := am.db.Exec("UPDATE auth SET privkey = ?", data)
    return err
}

//TOX DISABLED!!!
//
//func (am *AuthManager) GetToxKey() ([]byte, error) {
//    if am.db == nil {
//        return nil, fmt.Errorf("database is not open")
//    }
//    if am.toxKey == nil {
//        return nil, nil
//    }
//    return am.toxKey, nil
//}//

//func (am *AuthManager) SetToxKey(data []byte) error {
//    if am.db == nil {
//        return fmt.Errorf("database is not open")
//    }
//    am.toxKey = data
//    _, err := am.db.Exec("UPDATE auth SET tox_key = ?", data)
//    return err
//}//

//func (am *AuthManager) GetToxSave() ([]byte, error) {
//    if am.db == nil {
//        return nil, fmt.Errorf("database is not open")
//    }
//    if am.toxSave == nil {
//        return nil, nil
//    }
//    return am.toxSave, nil
//}//

//func (am *AuthManager) SetToxSave(data []byte) error {
//    if am.db == nil {
//        return fmt.Errorf("database is not open")
//    }
//    am.toxSave = data
//    _, err := am.db.Exec("UPDATE auth SET tox_save = ?", data)
//    return err
//}
//
//TOX DISABLED!!!

func (am *AuthManager) ChangePassword(oldPassword, newPassword string) error {
    if _, err := os.Stat(am.dbPath); os.IsNotExist(err) {
        return fmt.Errorf("database not found")
    }
    tempFile, err := os.CreateTemp("", "gramium_rekey_*.db")
    if err != nil {
        return fmt.Errorf("failed to create temporary file: %w", err)
    }
    tempPath := tempFile.Name()
    tempFile.Close()
    defer os.Remove(tempPath)

    if err := am.decryptFile(am.dbPath, tempPath, oldPassword); err != nil {
        return fmt.Errorf("invalid old password: %w", err)
    }
    if err := am.encryptFile(tempPath, am.dbPath, newPassword); err != nil {
        return fmt.Errorf("failed to re-encrypt: %w", err)
    }
    if am.password != "" && am.password == oldPassword {
        am.password = newPassword
    }
    fmt.Println("[OK] Password changed successfully")
    return nil
}