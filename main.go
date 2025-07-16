package main

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "log"
    "net/http"
    "sync"
    "time"
    "github.com/google/uuid"
    "github.com/gorilla/handlers"
    "github.com/gorilla/websocket"
    "github.com/jackc/pgx/v5/pgxpool"
    "golang.org/x/crypto/bcrypt"
    "golang.org/x/crypto/nacl/box"
)

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
}
var clients = make(map[*websocket.Conn]string)
var clientsMutex sync.Mutex
var broadcast = make(chan Message)
var userConnections = make(map[string]int) // Track connections per user
const maxConnectionsPerUser = 2           // Limit to prevent flooding

type User struct {
    ID        string    `json:"id"`
    Username  string    `json:"username"`
    Password  string    `json:"-"` // Not exposed in JSON
    PublicKey string    `json:"public_key"`
    CreatedAt time.Time `json:"created_at"`
}

type Message struct {
    ID        string    `json:"id"`
    ChatID    string    `json:"chat_id"`
    SenderID  string    `json:"sender_id"`
    Content   string    `json:"content"`
    Timestamp int64     `json:"timestamp"`
    Status    string    `json:"status"`
}

type Chat struct {
    ID           string    `json:"id"`
    Type         string    `json:"type"`
    Participants []string  `json:"participants"`
    Name         string    `json:"name,omitempty"`
    CreatedAt    time.Time `json:"created_at"`
}

func main() {
    // PostgreSQL connection pool
    pool, err := pgxpool.New(context.Background(), "postgres://postgres:admin@localhost:5432/chatdb")
    if err != nil {
        log.Fatal("Failed to connect to PostgreSQL:", err)
    }
    defer pool.Close()

    // Ping to verify connection
    if err := pool.Ping(context.Background()); err != nil {
        log.Fatal("Failed to ping PostgreSQL:", err)
    }
    log.Println("Connected to PostgreSQL!")

    // Drop existing tables to ensure clean schema
    _, err = pool.Exec(context.Background(), `
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS chat_participants;
        DROP TABLE IF EXISTS chats;
        DROP TABLE IF EXISTS users;
    `)
    if err != nil {
        log.Fatal("Failed to drop existing tables:", err)
    }

    // Initialize database schema
    _, err = pool.Exec(context.Background(), `
        CREATE TABLE users (
            id UUID PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL
        );
        CREATE TABLE chats (
            id UUID PRIMARY KEY,
            type TEXT NOT NULL,
            name TEXT,
            created_at TIMESTAMP NOT NULL
        );
        CREATE TABLE chat_participants (
            chat_id UUID REFERENCES chats(id),
            user_id UUID REFERENCES users(id),
            PRIMARY KEY (chat_id, user_id)
        );
        CREATE TABLE messages (
            id UUID PRIMARY KEY,
            chat_id UUID REFERENCES chats(id),
            sender_id UUID REFERENCES users(id),
            content TEXT NOT NULL,
            timestamp BIGINT NOT NULL,
            status TEXT NOT NULL
        );
    `)
    if err != nil {
        log.Fatal("Failed to initialize schema:", err)
    }

    // Insert dummy users
    dummyUsers := []User{
        {
            ID:        uuid.New().String(),
            Username:  "alice",
            Password:  "password123",
            PublicKey: base64.StdEncoding.EncodeToString(generateKeyPair().publicKey[:]),
            CreatedAt: time.Now(),
        },
        {
            ID:        uuid.New().String(),
            Username:  "bob",
            Password:  "password456",
            PublicKey: base64.StdEncoding.EncodeToString(generateKeyPair().publicKey[:]),
            CreatedAt: time.Now(),
        },
    }
    insertedUsers := make([]User, 0)
    for _, user := range dummyUsers {
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
        if err != nil {
            log.Printf("Failed to hash password for %s: %v", user.Username, err)
            continue
        }
        _, err = pool.Exec(context.Background(),
            `INSERT INTO users (id, username, password, public_key, created_at) 
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (username) DO NOTHING`,
            user.ID, user.Username, hashedPassword, user.PublicKey, user.CreatedAt)
        if err != nil {
            log.Printf("Failed to insert dummy user %s: %v", user.Username, err)
            continue
        }
        log.Printf("Inserted user %s with ID %s", user.Username, user.ID)
        insertedUsers = append(insertedUsers, user)
    }

    // Create a default chat for dummy users only if users were inserted
    if len(insertedUsers) > 0 {
        chatID := uuid.New().String()
        _, err = pool.Exec(context.Background(),
            `INSERT INTO chats (id, type, created_at) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
            chatID, "direct", time.Now())
        if err != nil {
            log.Fatal("Failed to create default chat:", err)
        }
        for _, user := range insertedUsers {
            _, err := pool.Exec(context.Background(),
                `INSERT INTO chat_participants (chat_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
                chatID, user.ID)
            if err != nil {
                log.Fatal("Failed to add participant %s to default chat: %v", user.Username, err)
            }
        }
    } else {
        log.Fatal("No users inserted, cannot create default chat")
    }

    // Define CORS middleware
    corsHandler := handlers.CORS(
        handlers.AllowedOrigins([]string{"http://localhost:5173"}),
        handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
        handlers.AllowedHeaders([]string{"Content-Type"}),
    )

    // Handlers
    http.Handle("/ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        handleWebSocket(w, r, pool)
    }))
    http.Handle("/register", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        handleRegister(w, r, pool)
    })))
    http.Handle("/login", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        handleLogin(w, r, pool)
    })))
    http.Handle("/create-chat", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        handleCreateChat(w, r, pool)
    })))
    http.Handle("/get-public-key", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        handleGetPublicKey(w, r, pool)
    })))
    http.Handle("/get-user-id", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        handleGetUserID(w, r, pool)
    })))
    http.Handle("/get-users", corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        handleGetUsers(w, r, pool)
    })))

    // Broadcast messages
    go handleMessages()

    log.Println("Server started on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func generateKeyPair() *boxKeyPair {
    publicKey, secretKey, _ := box.GenerateKey(rand.Reader)
    return &boxKeyPair{publicKey: *publicKey, secretKey: *secretKey}
}

type boxKeyPair struct {
    publicKey [32]byte
    secretKey [32]byte
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool) {
    userID := r.URL.Query().Get("user_id")
    if userID == "" {
        log.Println("WebSocket connection rejected: missing user_id")
        http.Error(w, "Missing user_id", http.StatusBadRequest)
        return
    }

    // Check connection limit
    clientsMutex.Lock()
    if userConnections[userID] >= maxConnectionsPerUser {
        clientsMutex.Unlock()
        log.Printf("WebSocket connection rejected: user %s reached connection limit (%d)", userID, maxConnectionsPerUser)
        http.Error(w, "Too many connections", http.StatusTooManyRequests)
        return
    }
    userConnections[userID]++
    clientsMutex.Unlock()

    ws, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        clientsMutex.Lock()
        userConnections[userID]--
        clientsMutex.Unlock()
        log.Println("WebSocket upgrade error:", err)
        return
    }

    // Register client
    clientsMutex.Lock()
    clients[ws] = userID
    clientsMutex.Unlock()
    log.Printf("Client connected: %s (Connections: %d)", userID, userConnections[userID])

    // Clean up on disconnect
    defer func() {
        clientsMutex.Lock()
        delete(clients, ws)
        userConnections[userID]--
        if userConnections[userID] == 0 {
            delete(userConnections, userID)
        }
        clientsMutex.Unlock()
        ws.Close()
        log.Printf("Client disconnected: %s (Connections: %d)", userID, userConnections[userID])
    }()

    // Set up ping/pong
    ws.SetReadDeadline(time.Now().Add(60 * time.Second))
    ws.SetPongHandler(func(string) error {
        ws.SetReadDeadline(time.Now().Add(60 * time.Second))
        return nil
    })
    go func() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                clientsMutex.Lock()
                if _, ok := clients[ws]; !ok {
                    clientsMutex.Unlock()
                    return
                }
                clientsMutex.Unlock()
                if err := ws.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
                    log.Printf("WebSocket ping error for user %s: %v", userID, err)
                    return
                }
            }
        }
    }()

    // Mark pending messages as delivered
    ctx := context.Background()
    _, err = pool.Exec(ctx,
        `UPDATE messages SET status = 'delivered' 
         WHERE chat_id IN (SELECT chat_id FROM chat_participants WHERE user_id = $1) 
         AND status = 'sent'`,
        userID)
    if err != nil {
        log.Println("Failed to update message status to delivered:", err)
    }

    for {
        var msg Message
        err := ws.ReadJSON(&msg)
        if err != nil {
            log.Printf("WebSocket read error for user %s: %v", userID, err)
            break
        }

        // Encrypt message
        encryptedContent, err := encryptMessage(msg.Content, msg.SenderID, msg.ChatID, pool)
        if err != nil {
            log.Printf("Encryption error for user %s: %v", userID, err)
            continue
        }
        msg.ID = uuid.New().String()
        msg.Content = encryptedContent

        // Save to PostgreSQL
        _, err = pool.Exec(ctx,
            `INSERT INTO messages (id, chat_id, sender_id, content, timestamp, status) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
            msg.ID, msg.ChatID, msg.SenderID, msg.Content, msg.Timestamp, msg.Status)
        if err != nil {
            log.Printf("PostgreSQL insert error for user %s: %v", userID, err)
            continue
        }

        // Broadcast message
        broadcast <- msg
    }
}

func handleMessages() {
    for {
        msg := <-broadcast
        log.Printf("Broadcasting message: %+v", msg)
        clientsMutex.Lock()
        for client, userID := range clients {
            if isParticipant(userID, msg.ChatID) && userID != msg.SenderID {
                err := client.WriteJSON(msg)
                if err != nil {
                    log.Printf("WebSocket write error for user %s: %v", userID, err)
                    client.Close()
                    delete(clients, client)
                    userConnections[userID]--
                    if userConnections[userID] == 0 {
                        delete(userConnections, userID)
                    }
                } else {
                    // Update status to delivered
                    err = client.WriteJSON(map[string]string{
                        "message_id": msg.ID,
                        "status":     "delivered",
                    })
                    if err != nil {
                        log.Printf("WebSocket write error for status update, user %s: %v", userID, err)
                    }
                }
            }
        }
        clientsMutex.Unlock()
    }
}

func encryptMessage(content, senderID, chatID string, pool *pgxpool.Pool) (string, error) {
    ctx := context.Background()
    var publicKey, secretKey string
    err := pool.QueryRow(ctx,
        `SELECT u1.public_key, u2.public_key 
         FROM users u1 
         JOIN chat_participants cp ON u1.id = cp.user_id 
         JOIN users u2 ON u2.id = $1
         WHERE cp.chat_id = $2 AND u1.id != $1`,
        senderID, chatID).Scan(&publicKey, &secretKey)
    if err != nil {
        return "", err
    }

    pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
    if err != nil {
        return "", err
    }
    secretKeyBytes, err := base64.StdEncoding.DecodeString(secretKey)
    if err != nil {
        return "", err
    }

    var pubKey, secretKeyArr [32]byte
    copy(pubKey[:], pubKeyBytes)
    copy(secretKeyArr[:], secretKeyBytes)

    nonce := [24]byte{}
    if _, err := rand.Read(nonce[:]); err != nil {
        return "", err
    }

    encrypted := box.Seal(nonce[:], []byte(content), &nonce, &pubKey, &secretKeyArr)
    return base64.StdEncoding.EncodeToString(encrypted), nil
}

func isParticipant(userID, chatID string) bool {
    return true // Placeholder
}

func handleRegister(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool) {
    if r.Method != http.MethodPost {
        http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
        return
    }
    user.ID = uuid.New().String()
    user.CreatedAt = time.Now()
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, `{"error":"Failed to hash password"}`, http.StatusInternalServerError)
        return
    }
    ctx := context.Background()
    _, err = pool.Exec(ctx,
        `INSERT INTO users (id, username, password, public_key, created_at) 
         VALUES ($1, $2, $3, $4, $5)`,
        user.ID, user.Username, hashedPassword, user.PublicKey, user.CreatedAt)
    if err != nil {
        http.Error(w, `{"error":"Failed to register user"}`, http.StatusInternalServerError)
        log.Println("Register error:", err)
        return
    }
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(user)
}

func handleLogin(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool) {
    if r.Method != http.MethodPost {
        http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }
    var credentials struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
        http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
        return
    }
    log.Printf("Login attempt for username: %s", credentials.Username)
    var user User
    var hashedPassword string
    ctx := context.Background()
    err := pool.QueryRow(ctx,
        `SELECT id, username, password, public_key, created_at FROM users WHERE username = $1`,
        credentials.Username).Scan(&user.ID, &user.Username, &hashedPassword, &user.PublicKey, &user.CreatedAt)
    if err != nil {
        log.Printf("User not found or query error: %v", err)
        http.Error(w, `{"error":"Invalid username or password"}`, http.StatusUnauthorized)
        return
    }
    if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
        log.Printf("Password mismatch for user %s: %v", credentials.Username, err)
        http.Error(w, `{"error":"Invalid username or password"}`, http.StatusUnauthorized)
        return
    }
    log.Printf("Login successful for user: %s", credentials.Username)
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(user)
}

func handleCreateChat(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool) {
    if r.Method != http.MethodPost {
        http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }
    var chat Chat
    if err := json.NewDecoder(r.Body).Decode(&chat); err != nil {
        http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
        return
    }
    chat.ID = uuid.New().String()
    chat.CreatedAt = time.Now()
    ctx := context.Background()

    // Validate participants
    for _, participant := range chat.Participants {
        var exists bool
        err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, participant).Scan(&exists)
        if err != nil {
            http.Error(w, `{"error":"Failed to validate participant"}`, http.StatusInternalServerError)
            log.Println("Participant validation error:", err)
            return
        }
        if !exists {
            http.Error(w, `{"error":"Participant not found: `+participant+`"}`, http.StatusBadRequest)
            return
        }
    }

    // Create chat
    _, err := pool.Exec(ctx,
        `INSERT INTO chats (id, type, name, created_at) 
         VALUES ($1, $2, $3, $4)`,
        chat.ID, chat.Type, chat.Name, chat.CreatedAt)
    if err != nil {
        http.Error(w, `{"error":"Failed to create chat"}`, http.StatusInternalServerError)
        log.Println("Create chat error:", err)
        return
    }
    for _, participant := range chat.Participants {
        _, err := pool.Exec(ctx,
            `INSERT INTO chat_participants (chat_id, user_id) 
             VALUES ($1, $2) ON CONFLICT DO NOTHING`,
            chat.ID, participant)
        if err != nil {
            http.Error(w, `{"error":"Failed to add participant"}`, http.StatusInternalServerError)
            log.Println("Participant error:", err)
            return
        }
    }
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(chat)
}

func handleGetPublicKey(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool) {
    if r.Method != http.MethodGet {
        http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }
    userID := r.URL.Query().Get("user_id")
    var publicKey string
    ctx := context.Background()
    err := pool.QueryRow(ctx,
        `SELECT public_key FROM users WHERE id = $1`, userID).Scan(&publicKey)
    if err != nil {
        http.Error(w, `{"error":"User not found"}`, http.StatusNotFound)
        return
    }
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"public_key": publicKey})
}

func handleGetUserID(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool) {
    if r.Method != http.MethodGet {
        http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }
    username := r.URL.Query().Get("username")
    var userID string
    ctx := context.Background()
    err := pool.QueryRow(ctx,
        `SELECT id FROM users WHERE username = $1`, username).Scan(&userID)
    if err != nil {
        http.Error(w, `{"error":"User not found"}`, http.StatusNotFound)
        return
    }
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"user_id": userID})
}

func handleGetUsers(w http.ResponseWriter, r *http.Request, pool *pgxpool.Pool) {
    if r.Method != http.MethodGet {
        http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }
    userID := r.URL.Query().Get("user_id")
    ctx := context.Background()
    rows, err := pool.Query(ctx, `SELECT id, username, public_key, created_at FROM users WHERE id != $1`, userID)
    if err != nil {
        http.Error(w, `{"error":"Failed to fetch users"}`, http.StatusInternalServerError)
        log.Println("Get users error:", err)
        return
    }
    defer rows.Close()

    users := []User{}
    for rows.Next() {
        var user User
        if err := rows.Scan(&user.ID, &user.Username, &user.PublicKey, &user.CreatedAt); err != nil {
            http.Error(w, `{"error":"Failed to scan users"}`, http.StatusInternalServerError)
            log.Println("Scan users error:", err)
            return
        }
        users = append(users, user)
    }
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(users)
}