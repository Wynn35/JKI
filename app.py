from flask import Flask, request, jsonify, render_template_string
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import sqlite3
import secrets
import base64
import os
import json
from datetime import datetime
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database setup
def init_db():
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            room_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            room_id INTEGER,
            username TEXT,
            encrypted_content TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (room_id) REFERENCES rooms (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Encryption functions
class SimpleCrypto:
    @staticmethod
    def generate_key():
        return base64.b64encode(os.urandom(32)).decode()
    
    @staticmethod
    def encrypt_message(message, key):
        key_bytes = base64.b64decode(key)
        iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode()
    
    @staticmethod
    def decrypt_message(encrypted_message, key):
        try:
            key_bytes = base64.b64decode(key)
            data = base64.b64decode(encrypted_message)
            iv = data[:16]
            encrypted_content = data[16:]
            
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
            
            # Unpadding
            unpadder = padding.PKCS7(128).unpadder()
            message = unpadder.update(padded_data) + unpadder.finalize()
            
            return message.decode()
        except:
            return None

# HTML Template - IMPROVED
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureChat - Fixed</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .auth-section { text-align: center; }
        .chat-section { display: none; }
        .form-group { margin: 10px 0; }
        input { padding: 10px; margin: 5px; border: 1px solid #ddd; border-radius: 5px; width: 200px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #0056b3; }
        #messages { 
            height: 300px; 
            overflow-y: scroll; 
            border: 1px solid #ddd; 
            padding: 15px; 
            margin: 10px 0; 
            background: #f9f9f9; 
        }
        .message { 
            margin: 10px 0; 
            padding: 12px; 
            border-radius: 8px; 
            border-left: 4px solid #2196f3;
            background: #e3f2fd;
        }
        .own-message { 
            background: #c8e6c9; 
            text-align: right; 
            border-left: 4px solid #4caf50;
            margin-left: 50px;
        }
        .system-message { 
            background: #fff3cd; 
            text-align: center; 
            font-style: italic; 
            border-left: 4px solid #ffc107;
        }
        .message-header {
            font-weight: bold;
            color: #666;
            font-size: 13px;
            margin-bottom: 5px;
        }
        .message-content {
            font-size: 15px;
            line-height: 1.4;
            word-wrap: break-word;
        }
        .message-time {
            font-size: 11px;
            color: #999;
            margin-top: 5px;
        }
        .error { color: red; margin: 10px 0; padding: 10px; background: #ffe6e6; border-radius: 5px; }
        .success { color: green; margin: 10px 0; padding: 10px; background: #e6ffe6; border-radius: 5px; }
        .encryption-status { 
            background: #d4edda; 
            padding: 12px; 
            border-radius: 8px; 
            margin: 15px 0; 
            text-align: center; 
            font-weight: bold; 
            border: 1px solid #c3e6cb;
        }
        .message-input-area {
            margin-top: 15px;
            display: flex;
            gap: 10px;
        }
        #messageInput {
            flex: 1;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
        }
        #messageInput:focus {
            border-color: #007bff;
            outline: none;
        }
        .connection-status {
            padding: 8px 12px;
            border-radius: 5px;
            font-size: 12px;
            margin-bottom: 10px;
        }
        .connected { background: #d4edda; color: #155724; }
        .disconnected { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 SecureChat - Fixed Version</h1>
        
        <!-- Authentication Section -->
        <div id="authSection" class="auth-section">
            <div id="errorMsg" class="error" style="display:none;"></div>
            <div id="successMsg" class="success" style="display:none;"></div>
            
            <!-- Login Form -->
            <div id="loginForm">
                <h3>Login</h3>
                <div class="form-group">
                    <input type="text" id="loginUsername" placeholder="Username" required>
                </div>
                <div class="form-group">  
                    <input type="password" id="loginPassword" placeholder="Password" required>
                </div>
                <button onclick="login()">Login</button>
                <button onclick="showRegister()">Register</button>
            </div>
            
            <!-- Register Form -->
            <div id="registerForm" style="display:none;">
                <h3>Register</h3>
                <div class="form-group">
                    <input type="text" id="regUsername" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" id="regPassword" placeholder="Password (min 8 chars)" required>
                </div>
                <button onclick="register()">Register</button>
                <button onclick="showLogin()">Back to Login</button>
            </div>
        </div>
        
        <!-- Chat Section -->
        <div id="chatSection" class="chat-section">
            <div class="encryption-status">
                🔒 All messages are encrypted with AES-256
            </div>
            
            <div id="connectionStatus" class="connection-status disconnected">
                🔴 Disconnected
            </div>
            
            <div>
                <strong>User:</strong> <span id="currentUser"></span>
                <button onclick="logout()" style="float: right;">Logout</button>
            </div>
            
            <!-- Room Selection -->
            <div style="margin: 20px 0;">
                <input type="text" id="roomName" placeholder="Enter room name">
                <button onclick="joinRoom()">Join/Create Room</button>
                <span id="currentRoom" style="margin-left: 20px; font-weight: bold;"></span>
            </div>
            
            <!-- Messages -->
            <div id="messages"></div>
            
            <!-- Message Input -->
            <div class="message-input-area">
                <input type="text" id="messageInput" placeholder="Type your message..." disabled>
                <button onclick="sendMessage()" id="sendBtn" disabled>Send</button>
            </div>
        </div>
    </div>

    <script>
        let socket;
        let currentUser;
        let currentRoomId;
        let currentRoomKey;
        let authToken;
        let isConnected = false;

        // Authentication functions
        async function login() {
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            if (!username || !password) {
                showError('Please fill all fields');
                return;
            }
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    authToken = data.token;
                    currentUser = username;
                    showSuccess('Login successful!');
                    showChatSection();
                } else {
                    showError(data.error);
                }
            } catch (error) {
                showError('Network error: ' + error.message);
            }
        }
        
        async function register() {
            const username = document.getElementById('regUsername').value;
            const password = document.getElementById('regPassword').value;
            
            if (!username || !password) {
                showError('Please fill all fields');
                return;
            }
            
            if (password.length < 8) {
                showError('Password must be at least 8 characters');
                return;
            }
            
            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showSuccess('Registration successful! Please login.');
                    showLogin();
                } else {
                    showError(data.error);
                }
            } catch (error) {
                showError('Network error: ' + error.message);
            }
        }
        
        function showRegister() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('registerForm').style.display = 'block';
            clearMessages();
        }
        
        function showLogin() {
            document.getElementById('registerForm').style.display = 'none';
            document.getElementById('loginForm').style.display = 'block';
            clearMessages();
        }
        
        function showChatSection() {
            document.getElementById('authSection').style.display = 'none';
            document.getElementById('chatSection').style.display = 'block';
            document.getElementById('currentUser').textContent = currentUser;
            
            // Initialize socket
            initializeSocket();
        }
        
        function initializeSocket() {
            console.log('Initializing socket connection...');
            socket = io();
            
            socket.on('connect', function() {
                console.log('✅ Connected to chat server');
                isConnected = true;
                updateConnectionStatus();
                displaySystemMessage('✅ Connected to secure chat server');
            });
            
            socket.on('disconnect', function() {
                console.log('❌ Disconnected from chat server');
                isConnected = false;
                updateConnectionStatus();
                displaySystemMessage('❌ Disconnected from server');
            });
            
            socket.on('receive_message', function(data) {
                console.log('📨 Received message:', data);
                displayMessage(data.username, data.message, data.username === currentUser);
            });
            
            socket.on('system_message', function(data) {
                console.log('📢 System message:', data);
                displaySystemMessage(data.message);
            });
            
            socket.on('user_joined', function(data) {
                console.log('👋 User joined:', data);
                displaySystemMessage('👋 ' + data.username + ' joined the room');
            });
            
            socket.on('user_left', function(data) {
                console.log('👋 User left:', data);
                displaySystemMessage('👋 ' + data.username + ' left the room');
            });
            
            socket.on('connect_error', function(error) {
                console.error('❌ Connection error:', error);
                showError('Connection failed: ' + error.message);
            });
        }
        
        function updateConnectionStatus() {
            const statusDiv = document.getElementById('connectionStatus');
            if (isConnected) {
                statusDiv.textContent = '🟢 Connected to secure server';
                statusDiv.className = 'connection-status connected';
            } else {
                statusDiv.textContent = '🔴 Disconnected from server';
                statusDiv.className = 'connection-status disconnected';
            }
        }
        
        async function joinRoom() {
            const roomName = document.getElementById('roomName').value;
            if (!roomName) {
                showError('Please enter a room name');
                return;
            }
            
            try {
                const response = await fetch('/join_room', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({ room_name: roomName })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    currentRoomId = data.room_id;
                    currentRoomKey = data.room_key;
                    document.getElementById('currentRoom').textContent = 'Room: ' + roomName;
                    document.getElementById('messageInput').disabled = false;
                    document.getElementById('sendBtn').disabled = false;
                    document.getElementById('messages').innerHTML = '';
                    
                    // Join socket room - FIXED
                    if (socket && isConnected) {
                        console.log('🏠 Joining room:', currentRoomId);
                        socket.emit('join_room', { 
                            room_id: currentRoomId, 
                            username: currentUser 
                        });
                    }
                    
                    displaySystemMessage('🔐 Joined encrypted room: ' + roomName);
                    document.getElementById('messageInput').focus();
                } else {
                    showError(data.error);
                }
            } catch (error) {
                showError('Network error: ' + error.message);
            }
        }
        
        function sendMessage() {
            const messageInput = document.getElementById('messageInput');
            const message = messageInput.value.trim();
            
            if (!message || !currentRoomId) {
                return;
            }
            
            if (!socket || !isConnected) {
                showError('Not connected to server. Please refresh the page.');
                return;
            }
            
            console.log('📤 Sending message:', message);
            
            socket.emit('send_message', {
                room_id: currentRoomId,
                message: message,
                username: currentUser,
                room_key: currentRoomKey
            });
            
            messageInput.value = '';
            messageInput.focus();
        }
        
        function displayMessage(username, message, isOwn) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message' + (isOwn ? ' own-message' : '');
            
            const now = new Date();
            const timeStr = now.toLocaleTimeString();
            
            messageDiv.innerHTML = `
                <div class="message-header">${escapeHtml(username)}</div>
                <div class="message-content">${escapeHtml(message)}</div>
                <div class="message-time">${timeStr}</div>
            `;
            
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
            
            console.log('💬 Message displayed:', username, message);
        }
        
        function displaySystemMessage(message) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message system-message';
            
            const now = new Date();
            const timeStr = now.toLocaleTimeString();
            
            messageDiv.innerHTML = `
                <div class="message-content">${escapeHtml(message)}</div>
                <div class="message-time">${timeStr}</div>
            `;
            
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        function logout() {
            if (socket) {
                socket.disconnect();
            }
            currentUser = null;
            currentRoomId = null;
            currentRoomKey = null;
            authToken = null;
            isConnected = false;
            document.getElementById('chatSection').style.display = 'none';
            document.getElementById('authSection').style.display = 'block';
            showLogin();
        }
        
        function showError(msg) {
            const errorDiv = document.getElementById('errorMsg');
            errorDiv.textContent = '❌ ' + msg;
            errorDiv.style.display = 'block';
            setTimeout(() => errorDiv.style.display = 'none', 5000);
        }
        
        function showSuccess(msg) {
            const successDiv = document.getElementById('successMsg');
            successDiv.textContent = '✅ ' + msg;
            successDiv.style.display = 'block';
            setTimeout(() => successDiv.style.display = 'none', 3000);
        }
        
        function clearMessages() {
            document.getElementById('errorMsg').style.display = 'none';
            document.getElementById('successMsg').style.display = 'none';
        }
        
        function escapeHtml(unsafe) {
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
        
        // Enter key support
        document.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                if (document.getElementById('messageInput') === document.activeElement) {
                    sendMessage();
                } else if (document.getElementById('loginPassword') === document.activeElement) {
                    login();
                } else if (document.getElementById('regPassword') === document.activeElement) {
                    register();
                } else if (document.getElementById('roomName') === document.activeElement) {
                    joinRoom();
                }
            }
        });
        
        // Auto-reconnect when connection is lost
        setInterval(function() {
            if (!isConnected && socket) {
                console.log('🔄 Attempting to reconnect...');
                socket.connect();
            }
        }, 5000);
    </script>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400
    
    # Create user
    password_hash = generate_password_hash(password)
    cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                   (username, password_hash))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Registration successful'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not check_password_hash(user[0], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate simple JWT token
    token = jwt.encode({'username': username}, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({'token': token, 'message': 'Login successful'}), 200

@app.route('/join_room', methods=['POST'])
def join_room_http():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload['username']
    except:
        return jsonify({'error': 'Invalid token'}), 401
    
    data = request.get_json()
    room_name = data.get('room_name')
    
    if not room_name:
        return jsonify({'error': 'Room name required'}), 400
    
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    
    # Check if room exists
    cursor.execute('SELECT id, room_key FROM rooms WHERE name = ?', (room_name,))
    room = cursor.fetchone()
    
    if room:
        room_id, room_key = room
    else:
        # Create new room
        room_key = SimpleCrypto.generate_key()
        cursor.execute('INSERT INTO rooms (name, room_key) VALUES (?, ?)', 
                       (room_name, room_key))
        room_id = cursor.lastrowid
        conn.commit()
    
    conn.close()
    
    return jsonify({
        'room_id': room_id,
        'room_key': room_key,
        'message': 'Joined room successfully'
    }), 200

# Socket.IO events - FIXED
@socketio.on('connect')
def on_connect():
    print(f'✅ User connected: {request.sid}')

@socketio.on('disconnect')
def on_disconnect():
    print(f'❌ User disconnected: {request.sid}')

@socketio.on('join_room')
def on_join_room(data):
    try:
        room_id = str(data['room_id'])
        username = data['username']
        
        print(f'🏠 {username} joining room {room_id}')
        
        # FIXED: Use Flask-SocketIO's join_room correctly
        join_room(room_id)
        
        print(f'✅ {username} successfully joined room {room_id}')
        
        # Notify other users
        emit('user_joined', {'username': username}, room=room_id, include_self=False)
        
    except Exception as e:
        print(f'❌ Error in join_room: {e}')

@socketio.on('send_message')
def on_send_message(data):
    try:
        room_id = str(data['room_id'])
        message = data['message']
        username = data['username']
        room_key = data['room_key']
        
        print(f'📨 Processing message from {username} in room {room_id}: {message}')
        
        # Encrypt message
        encrypted_message = SimpleCrypto.encrypt_message(message, room_key)
        
        # Store in database
        conn = sqlite3.connect('chat.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO messages (room_id, username, encrypted_content) VALUES (?, ?, ?)',
                       (room_id, username, encrypted_message))
        conn.commit()
        conn.close()
        
        print(f'💾 Message stored and broadcasting to room {room_id}')
        
        # Send to all room members (including sender)
        emit('receive_message', {
            'username': username,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }, room=room_id, include_self=True)
        
        print(f'✅ Message broadcasted successfully')
        
    except Exception as e:
        print(f'❌ Error in send_message: {e}')

if __name__ == '__main__':
    init_db()
    print("🔐 Starting SecureChat - Railway Deployment...")
    
    # Railway menyediakan PORT via environment variable
    port = int(os.environ.get('PORT', 5000))
    
    # Mode production untuk Railway
    socketio.run(
        app, 
        debug=False,  # PENTING: False untuk production
        host='0.0.0.0',  # Listen pada semua interface
        port=port,
        allow_unsafe_werkzeug=True  # Untuk Flask-SocketIO di production
    )