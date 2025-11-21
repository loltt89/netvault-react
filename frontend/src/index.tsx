import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import './styles/themes.css';
import App from './App';
import { AuthProvider } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import './i18n/config';
import reportWebVitals from './reportWebVitals';

// Suppress ResizeObserver loop warnings from Monaco Editor
// and WebSocket cleanup warnings from React Strict Mode
// These are harmless and don't affect functionality
const resizeObserverErrorHandler = (e: ErrorEvent) => {
  if (e.message && (
    e.message.includes('ResizeObserver loop') ||
    e.message.includes('WebSocket is closed before the connection is established')
  )) {
    e.stopImmediatePropagation();
    e.preventDefault();
    return false;
  }
};

// Also suppress in console errors
const originalError = console.error;
console.error = (...args: any[]) => {
  if (args[0] && typeof args[0] === 'string' && (
    args[0].includes('ResizeObserver loop') ||
    args[0].includes('WebSocket is closed before the connection is established')
  )) {
    return;
  }
  originalError.apply(console, args);
};

window.addEventListener('error', resizeObserverErrorHandler);

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);
root.render(
  <React.StrictMode>
    <ThemeProvider>
      <AuthProvider>
        <App />
      </AuthProvider>
    </ThemeProvider>
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
