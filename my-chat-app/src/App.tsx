import React, { useState, useEffect } from 'react';
import { Buffer } from 'buffer';
import * as nacl from 'tweetnacl';
import { format } from 'date-fns';
import { useNavigate } from 'react-router-dom';

interface Message {
  id: string;
  chat_id: string;
  sender_id: string;
  content: string;
  timestamp: number;
  status: string;
}

interface User {
  id: string;
  username: string;
  public_key: string;
}

interface AppProps {
  user: User | null;
}

const App: React.FC<AppProps> = ({ user }) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [chatId, setChatId] = useState<string | null>(null);
  const [recipientPublicKey, setRecipientPublicKey] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const { publicKey, secretKey } = nacl.box.keyPair();
  const [reconnectAttempts, setReconnectAttempts] = useState(0);
  const maxReconnectAttempts = 5;
  const baseReconnectDelay = 3000;

  const connectWebSocket = () => {
    if (!user) return;
    if (reconnectAttempts >= maxReconnectAttempts) {
      setError('Failed to connect to WebSocket after multiple attempts');
      return;
    }

    const socket = new WebSocket(`ws://localhost:8080/ws?user_id=${user.id}`);
    socket.onopen = () => {
      console.log('WebSocket connected');
      setWs(socket);
      setReconnectAttempts(0); // Reset on successful connection
      setError(null);
    };
    socket.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log('WebSocket message received:', data);
        if (data.message_id) {
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === data.message_id ? { ...msg, status: data.status } : msg
            )
          );
        } else if (data.chat_id === chatId) {
          const decrypted = await decryptMessage(data.content, data.sender_id, data.chat_id);
          setMessages((prev) => [...prev, { ...data, content: decrypted }]);
        }
      } catch (err) {
        console.error('WebSocket message processing error:', err);
        setError('Failed to process message');
      }
    };
    socket.onclose = (event) => {
      console.log(`WebSocket closed: code=${event.code}, reason=${event.reason}`);
      setWs(null);
      const delay = baseReconnectDelay * Math.pow(2, reconnectAttempts);
      setTimeout(() => {
        setReconnectAttempts((prev) => prev + 1);
        connectWebSocket();
      }, delay);
    };
    socket.onerror = (err) => {
      console.error('WebSocket error:', err);
      setError('WebSocket connection error');
    };
    // socket.onping = () => {
    //   console.log('Received ping from server');
    //   socket.pong();
    // };
  };

  useEffect(() => {
    if (!user) {
      navigate('/login');
      return;
    }

    // Fetch all users
    fetch(`http://localhost:8080/get-users?user_id=${user.id}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`Failed to fetch users: ${res.statusText}`);
        return res.json();
      })
      .then((data) => {
        console.log('Users fetched:', data);
        setUsers(data);
      })
      .catch((err) => {
        console.error('Failed to fetch users:', err);
        setError('Failed to load users');
      });

    // Initialize WebSocket
    if (!ws) {
      connectWebSocket();
    }

    return () => {
      if (ws) {
        ws.close();
      }
    };
  }, [user, ws, chatId, navigate]);

  const selectUser = async (recipient: User) => {
    setSelectedUser(recipient);
    setMessages([]);
    setError(null);

    try {
      // Create chat
      const res = await fetch('http://localhost:8080/create-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'direct',
          participants: [user!.id, recipient.id],
          created_at: new Date().toISOString(),
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to create chat');
      }
      const chat = await res.json();
      console.log('Chat created:', chat);
      setChatId(chat.id);

      // Fetch recipient's public key
      const keyRes = await fetch(`http://localhost:8080/get-public-key?user_id=${recipient.id}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!keyRes.ok) {
        const data = await keyRes.json();
        throw new Error(data.error || 'Failed to fetch public key');
      }
      const keyData = await keyRes.json();
      setRecipientPublicKey(Buffer.from(keyData.public_key, 'base64'));
    } catch (err: any) {
      console.error('Error selecting user:', err);
      setError(err.message || 'Failed to start chat');
    }
  };

  const sendMessage = async () => {
    if (!ws) {
      console.error('Send failed: No WebSocket connection');
      setError('No WebSocket connection');
      return;
    }
    if (!input) {
      console.error('Send failed: No input');
      setError('Please enter a message');
      return;
    }
    if (!recipientPublicKey) {
      console.error('Send failed: No recipient public key');
      setError('Recipient public key not loaded');
      return;
    }
    if (!user) {
      console.error('Send failed: No user');
      setError('User not logged in');
      return;
    }
    if (!chatId) {
      console.error('Send failed: No chat ID');
      setError('Chat not initialized');
      return;
    }

    try {
      const encrypted = await encryptMessage(input, user.id, chatId);
      const message: Message = {
        id: uuid(),
        chat_id: chatId,
        sender_id: user.id,
        content: encrypted,
        timestamp: Date.now(),
        status: 'sent',
      };
      console.log('Sending message:', message);
      ws.send(JSON.stringify(message));
      setMessages((prev) => [...prev, { ...message, content: input }]);
      setInput('');
    } catch (err) {
      console.error('Send message error:', err);
      setError('Failed to send message');
    }
  };

  const encryptMessage = async (content: string, senderId: string, chatId: string): Promise<string> => {
    const nonce = nacl.randomBytes(24);
    const encrypted = nacl.box(
      Buffer.from(content),
      nonce,
      recipientPublicKey!,
      secretKey
    );
    return Buffer.concat([nonce, encrypted]).toString('base64');
  };

  const decryptMessage = async (content: string, senderId: string, chatId: string): Promise<string> => {
    if (!user || !selectedUser) return 'Decryption failed: No user';
    const senderPublicKey = Buffer.from(selectedUser.public_key, 'base64');
    const data = Buffer.from(content, 'base64');
    const nonce = data.slice(0, 24);
    const ciphertext = data.slice(24);
    const decrypted = nacl.box.open(ciphertext, nonce, senderPublicKey, secretKey);
    return decrypted ? Buffer.from(decrypted).toString() : 'Decryption failed';
  };

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div className="flex h-screen bg-white">
      {/* Sidebar: User List */}
      <div className="w-1/4 bg-gray-100 border-r p-4">
        <h2 className="text-lg font-bold mb-4">Messages</h2>
        {users.length === 0 && <p className="text-gray-500">No users available</p>}
        {users.map((u) => (
          <div
            key={u.id}
            onClick={() => selectUser(u)}
            className={`p-2 rounded cursor-pointer hover:bg-gray-200 ${
              selectedUser?.id === u.id ? 'bg-gray-300' : ''
            }`}
          >
            {u.username}
          </div>
        ))}
      </div>
      {/* Chat Area */}
      <div className="flex flex-col flex-1">
        <div className="flex items-center p-4 bg-gray-100 border-b">
          <h1 className="text-lg font-semibold">{selectedUser ? selectedUser.username : 'Select a user'}</h1>
        </div>
        {error && <div className="p-4 text-red-500 text-center">{error}</div>}
        <div className="flex-1 p-4 overflow-y-auto">
          {selectedUser ? (
            messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex mb-2 ${msg.sender_id === user.id ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-xs p-3 rounded-2xl ${
                    msg.sender_id === user.id ? 'bg-blue-500 text-white' : 'bg-gray-200 text-black'
                  }`}
                >
                  <p>{msg.content}</p>
                  <div className="text-xs text-gray-500 mt-1">
                    {format(new Date(msg.timestamp), 'h:mm a')}
                    {msg.sender_id === user.id && (
                      <span className="ml-2">
                        {msg.status === 'sent' ? '✓' : '✓✓'}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center text-gray-500">Select a user to start chatting</div>
          )}
        </div>
        {selectedUser && (
          <div className="flex p-4 bg-gray-100 border-t">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Type a message..."
              className="flex-1 p-2 rounded-full border-none bg-white focus:outline-none"
            />
            <button
              onClick={sendMessage}
              className="ml-2 bg-blue-500 text-white p-2 rounded-full hover:bg-blue-600"
            >
              Send
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;

function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = (Math.random() * 16) | 0,
      v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}