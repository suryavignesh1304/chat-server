import React, { useState } from 'react';
  import { useNavigate } from 'react-router-dom';

  const Login: React.FC = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleLogin = async (e: React.FormEvent) => {
      e.preventDefault();
      try {
        const res = await fetch('http://localhost:8080/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || 'Login failed');
        }
        const user = await res.json();
        navigate('/chat', { state: { user } });
      } catch (err: any) {
        setError(err.message || 'Invalid username or password');
      }
    };

    return (
      <div className="flex items-center justify-center h-screen bg-gray-100">
        <form onSubmit={handleLogin} className="p-6 bg-white rounded-lg shadow-md w-96">
          <h2 className="text-2xl font-bold mb-4 text-center">Login</h2>
          {error && <p className="text-red-500 mb-4 text-center">{error}</p>}
          <div className="mb-4">
            <label className="block text-sm font-medium mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <div className="mb-4">
            <label className="block text-sm font-medium mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <button type="submit" className="w-full p-2 bg-blue-500 text-white rounded hover:bg-blue-600">
            Login
          </button>
        </form>
      </div>
    );
  };

  export default Login;