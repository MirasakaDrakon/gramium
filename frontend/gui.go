package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"image/color"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/term"

	"gramium/core"
)

// ---------- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ----------
var (
	state      *GUIState
	coreNode   *core.Node
	updateChan = make(chan struct{}, 1)
	window     *app.Window
	theme      *material.Theme
)

// ---------- СОСТОЯНИЕ GUI ----------
type GUIState struct {
	mu              sync.Mutex
	contacts        []core.PeerMeta
	messages        map[string][]Message
	selectedContact string
	protocol        string
	protocolLabel   string

	listContacts   widget.List
	listMessages   widget.List
	inputEditor    widget.Editor
	sendButton     widget.Clickable
	addButton      widget.Clickable
	protocolToggle widget.Clickable

	nameEditor widget.Editor
	peerEditor widget.Editor
	toxEditor  widget.Editor
	addContact widget.Clickable
}

type Message struct {
	FromMe    bool
	Text      string
	Timestamp time.Time
}

func NewGUIState() *GUIState {
	return &GUIState{
		messages:        make(map[string][]Message),
		protocol:        "gramium",
		protocolLabel:   "Gramium",
		listContacts:    widget.List{List: layout.List{Axis: layout.Vertical}},
		listMessages:    widget.List{List: layout.List{Axis: layout.Vertical}},
		inputEditor:     widget.Editor{SingleLine: true, Submit: true},
		nameEditor:      widget.Editor{SingleLine: true},
		peerEditor:      widget.Editor{SingleLine: true},
		toxEditor:       widget.Editor{SingleLine: true},
	}
}

// ---------- ОСНОВНАЯ ФУНКЦИЯ ----------
func main() {
	// 1. Аутентификация (как в cli.go)
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("Failed to get home directory:", err)
	}
	dbPath := filepath.Join(home, ".gramium", "encrypted-gramium.db")
	metaFile := filepath.Join(home, ".gramium", "meta.json")
	os.MkdirAll(filepath.Join(home, ".gramium"), 0700)

	authManager := core.NewAuthManager(dbPath)
	var password string
	var meta *core.PeerMeta

	isNewDB := false
	if _, err := os.Stat(dbPath); err != nil {
		isNewDB = true
	}

	meta = &core.PeerMeta{
		ClientName:    "Gramium-GUI",
		ClientVersion: "1.0.0",
		Status:        "online",
	}
	if data, err := os.ReadFile(metaFile); err == nil {
		json.Unmarshal(data, meta)
	}

	if isNewDB {
		fmt.Println("[AUTH] Welcome to Gramium GUI!")
		fmt.Print("Enter your username: ")
		var username string
		fmt.Scanln(&username)
		if username == "" {
			username = "user"
		}
		meta.Username = username

		fmt.Println("\nSelect authentication method:")
		fmt.Println("  1. Master key (password)")
		fmt.Println("  2. Username + password")
		fmt.Println("  3. Seed phrase (BIP-39)")
		fmt.Println("  4. AES-256 certificate file")
		fmt.Print("Choice (1-4): ")
		var methodStr string
		fmt.Scanln(&methodStr)
		method := 1
		if methodStr != "" {
			if m, err := strconv.Atoi(methodStr); err == nil && m >= 1 && m <= 4 {
				method = m
			}
		}

		switch method {
		case 1:
			fmt.Print("Create master key: ")
			pw := readPassword()
			fmt.Print("Repeat master key: ")
			pw2 := readPassword()
			if pw != pw2 {
				log.Fatal("Passwords do not match")
			}
			password = pw
		case 2:
			fmt.Print("Enter username (auth): ")
			var login string
			fmt.Scanln(&login)
			if login == "" {
				login = "user"
			}
			fmt.Print("Enter password: ")
			pw := readPassword()
			fmt.Print("Repeat password: ")
			pw2 := readPassword()
			if pw != pw2 {
				log.Fatal("Passwords do not match")
			}
			password = login + ";" + pw
		case 3:
			entropy, _ := bip39.NewEntropy(128)
			mnemonic, _ := bip39.NewMnemonic(entropy)
			fmt.Println("\nYour seed phrase (keep it safe):")
			fmt.Println("============================================")
			fmt.Println(mnemonic)
			fmt.Println("============================================")
			fmt.Print("\nPress Enter to continue...")
			fmt.Scanln()
			password = mnemonic
		case 4:
			fmt.Print("Enter path to certificate file (key.pem): ")
			var certPath string
			fmt.Scanln(&certPath)
			data, err := os.ReadFile(certPath)
			if err != nil {
				log.Fatal("Failed to read certificate file:", err)
			}
			password = string(data)
		}

		data, _ := json.Marshal(meta)
		os.WriteFile(metaFile, data, 0600)

		if err := authManager.CreateDatabase(password, meta, method); err != nil {
			log.Fatal("Failed to create database:", err)
		}
	} else {
		method, err := authManager.LoadAuthMeta()
		if err != nil {
			log.Fatal("Failed to load authentication method:", err)
		}
		fmt.Println("[AUTH] Please authenticate.")
		switch method {
		case 1:
			fmt.Print("Enter master key: ")
			password = readPassword()
		case 2:
			fmt.Print("Enter username (auth): ")
			var login string
			fmt.Scanln(&login)
			fmt.Print("Enter password: ")
			pw := readPassword()
			password = login + ";" + pw
		case 3:
			fmt.Print("Enter seed phrase (12 words): ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			password = scanner.Text()
		case 4:
			fmt.Print("Enter path to certificate file (key.pem): ")
			var certPath string
			fmt.Scanln(&certPath)
			data, err := os.ReadFile(certPath)
			if err != nil {
				log.Fatal("Failed to read certificate file:", err)
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
		log.Fatal("Failed to start node:", err)
	}
	coreNode = node
	node.Start()
	defer node.Stop()

	// 2. Инициализация GUI
	state = NewGUIState()
	state.refreshContacts()
	if len(state.contacts) > 0 {
		state.selectedContact = state.contacts[0].Username
	}
	state.refreshMessages()

	// Периодическое обновление
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				state.refreshContacts()
				state.refreshMessages()
				updateChan <- struct{}{}
			}
		}
	}()

	// 3. Запуск GioUI
	go func() {
		window = app.NewWindow(
			app.Title("Gramium"),
			app.Size(unit.Dp(1000), unit.Dp(700)),
			app.MinSize(unit.Dp(800), unit.Dp(600)),
		)
		if err := runGUI(); err != nil {
			log.Fatal(err)
		}
	}()
	app.Main()
}

// ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
func readPassword() string {
	fmt.Print(": ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatal("Failed to read password:", err)
	}
	return string(pw)
}

// ---------- ОБНОВЛЕНИЕ ДАННЫХ ----------
func (s *GUIState) refreshContacts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if coreNode == nil {
		return
	}
	list, err := coreNode.ListContacts()
	if err != nil {
		return
	}
	var contacts []core.PeerMeta
	for _, entry := range list {
		parts := strings.Fields(entry)
		if len(parts) == 0 {
			continue
		}
		name := parts[0]
		meta, err := coreNode.GetContactMeta(name)
		if err != nil {
			meta = &core.PeerMeta{Username: name}
		}
		contacts = append(contacts, *meta)
	}
	s.contacts = contacts
}

func (s *GUIState) refreshMessages() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if coreNode == nil || s.selectedContact == "" {
		return
	}
	// Используем экспортированное поле DB (должно быть с большой буквы в core.Node)
	db := coreNode.DB
	if db == nil {
		return
	}
	rows, err := db.Query(`
		SELECT is_outgoing, message, timestamp
		FROM messages
		WHERE contact_id = (SELECT id FROM contacts WHERE username = ? OR peer_id = ? OR tox_id = ?)
		ORDER BY timestamp ASC
	`, s.selectedContact, s.selectedContact, s.selectedContact)
	if err != nil {
		return
	}
	defer rows.Close()
	var msgs []Message
	for rows.Next() {
		var outgoing bool
		var text string
		var ts int64
		if err := rows.Scan(&outgoing, &text, &ts); err != nil {
			continue
		}
		msgs = append(msgs, Message{
			FromMe:    outgoing,
			Text:      text,
			Timestamp: time.Unix(ts, 0),
		})
	}
	s.messages[s.selectedContact] = msgs
}

// ---------- ЗАПУСК GUI ----------
func runGUI() error {
	theme = material.NewTheme()
	// Добавляем шрифты
	theme.Fonts = gofont.Collection()
	var ops op.Ops

	for {
		e := window.Event()
		switch e := e.(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			layoutUI(gtx, theme)
			e.Frame(gtx.Ops)
		}
	}
}

// ---------- ОСНОВНОЙ ЛЕЙАУТ ----------
func layoutUI(gtx layout.Context, th *material.Theme) {
	select {
	case <-updateChan:
		gtx = gtx
	default:
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// Фиксированная ширина 250dp
			width := int(float32(250) * float32(gtx.Metric.PxPerDp))
			gtx.Constraints.Max.X = width
			gtx.Constraints.Min.X = width
			return layoutContactPanel(gtx, th)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layoutChatPanel(gtx, th)
		}),
	)
}

// ---------- ЛЕВАЯ ПАНЕЛЬ ----------
func layoutContactPanel(gtx layout.Context, th *material.Theme) layout.Dimensions {
	// Фон тёмный
	paint.Fill(gtx.Ops, color.NRGBA{R: 0x2A, G: 0x30, B: 0x3C, A: 0xFF})

	return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Label(th, unit.Sp(18), "Contacts")
				label.Color = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
				return label.Layout(gtx)
			}),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return material.List(th, &state.listContacts).Layout(gtx, len(state.contacts), func(gtx layout.Context, idx int) layout.Dimensions {
					contact := state.contacts[idx]
					btn := material.Button(th, &state.listContacts.Button, contact.Username)
					if state.selectedContact == contact.Username {
						btn.Background = color.NRGBA{R: 0x4A, G: 0x90, B: 0xD9, A: 0xFF}
					}
					if btn.Button.Clicked(gtx) {
						state.selectedContact = contact.Username
						state.refreshMessages()
						updateChan <- struct{}{}
					}
					return btn.Layout(gtx)
				})
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						label := material.Label(th, unit.Sp(14), "Name:")
						label.Color = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
						return label.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.Editor(th, &state.nameEditor, "Name").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						label := material.Label(th, unit.Sp(14), "Peer ID (optional):")
						label.Color = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
						return label.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.Editor(th, &state.peerEditor, "Peer ID").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						label := material.Label(th, unit.Sp(14), "Tox ID (optional):")
						label.Color = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
						return label.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.Editor(th, &state.toxEditor, "Tox ID").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &state.addContact, "Add Contact")
						if btn.Button.Clicked(gtx) {
							name := state.nameEditor.Text()
							peerID := state.peerEditor.Text()
							toxID := state.toxEditor.Text()
							if name == "" {
								return layout.Dimensions{}
							}
							if err := coreNode.AddContact(name, peerID, toxID); err != nil {
								log.Printf("Failed to add contact: %v", err)
							} else {
								state.nameEditor.SetText("")
								state.peerEditor.SetText("")
								state.toxEditor.SetText("")
								state.refreshContacts()
								updateChan <- struct{}{}
							}
						}
						return btn.Layout(gtx)
					}),
				)
			}),
		)
	})
}

// ---------- ПРАВАЯ ПАНЕЛЬ ----------
func layoutChatPanel(gtx layout.Context, th *material.Theme) layout.Dimensions {
	paint.Fill(gtx.Ops, color.NRGBA{R: 0x34, G: 0x3B, B: 0x47, A: 0xFF})

	if state.selectedContact == "" {
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			label := material.Label(th, unit.Sp(18), "Select a contact")
			label.Color = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
			return label.Layout(gtx)
		})
	}

	msgs := state.messages[state.selectedContact]
	if msgs == nil {
		msgs = []Message{}
	}

	return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Label(th, unit.Sp(18), "Chat with "+state.selectedContact)
				label.Color = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
				return label.Layout(gtx)
			}),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return material.List(th, &state.listMessages).Layout(gtx, len(msgs), func(gtx layout.Context, idx int) layout.Dimensions {
					msg := msgs[idx]
					var align layout.Direction
					var textColor color.NRGBA
					if msg.FromMe {
						align = layout.E
						textColor = color.NRGBA{R: 0x4A, G: 0x90, B: 0xD9, A: 0xFF}
					} else {
						align = layout.W
						textColor = color.NRGBA{R: 0x7B, G: 0xED, B: 0x9F, A: 0xFF}
					}
					return align.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							label := material.Label(th, unit.Sp(14), msg.Text)
							label.Color = textColor
							return label.Layout(gtx)
						})
					})
				})
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return material.Editor(th, &state.inputEditor, "Type message...").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &state.protocolToggle, state.protocolLabel)
						if btn.Button.Clicked(gtx) {
							if state.protocol == "gramium" {
								state.protocol = "tox"
								state.protocolLabel = "Tox"
							} else {
								state.protocol = "gramium"
								state.protocolLabel = "Gramium"
							}
						}
						return btn.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &state.sendButton, "Send")
						if btn.Button.Clicked(gtx) {
							text := state.inputEditor.Text()
							if text != "" && state.selectedContact != "" {
								if err := coreNode.SendMessage(state.selectedContact, []byte(text), state.protocol); err == nil {
									state.messages[state.selectedContact] = append(state.messages[state.selectedContact], Message{
										FromMe:    true,
										Text:      text,
										Timestamp: time.Now(),
									})
									state.inputEditor.SetText("")
									updateChan <- struct{}{}
								} else {
									log.Printf("Send error: %v", err)
								}
							}
						}
						return btn.Layout(gtx)
					}),
				)
			}),
		)
	})
}