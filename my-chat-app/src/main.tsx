import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import App from './App';
import Login from './Login';
import './index.css';

const Main: React.FC = () => {
  const location = useLocation();
  const { user } = location.state || { user: null };

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/chat" element={<App user={user} />} />
      <Route path="/" element={<Login />} />
    </Routes>
  );
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Main />
    </BrowserRouter>
  </React.StrictMode>
);