import React, { useEffect, useRef } from 'react';
import './TaskTerminal.css';

interface LogEntry {
  type: string;
  text: string;
  device_name: string;
  timestamp?: string;
}

interface TaskTerminalProps {
  logs: LogEntry[];
  onClose: () => void;
  isConnected: boolean;
  onClear: () => void;
}

const TaskTerminal: React.FC<TaskTerminalProps> = ({ logs, onClose, isConnected, onClear }) => {
  const terminalContentRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (terminalContentRef.current) {
      terminalContentRef.current.scrollTop = terminalContentRef.current.scrollHeight;
    }
  }, [logs]);

  const getLogClass = (type: string) => {
    switch (type) {
      case 'error':
        return 'log-error';
      case 'success':
        return 'log-success';
      case 'warn':
        return 'log-warn';
      case 'info':
      default:
        return 'log-info';
    }
  };

  const formatTime = () => {
    return new Date().toLocaleTimeString('en-US', { hour12: false });
  };

  return (
    <div className="realtime-terminal">
      <div className="terminal-header">
        <div className="terminal-title">
          <span className="terminal-icon">⚡</span>
          <h4>Real-time Task Log</h4>
          <span className={`connection-indicator ${isConnected ? 'connected' : 'disconnected'}`}>
            {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
          </span>
        </div>
        <div className="terminal-controls">
          <button onClick={onClear} className="btn-terminal-clear" title="Clear logs">
            🗑️ Clear
          </button>
          <button onClick={onClose} className="btn-terminal-close" title="Close terminal">
            ✕
          </button>
        </div>
      </div>

      <div className="terminal-content" ref={terminalContentRef}>
        {logs.length === 0 ? (
          <div className="log-entry log-info">
            <span>[{formatTime()}]</span>
            <span>[System]</span>
            <span>Waiting for backup tasks...</span>
          </div>
        ) : (
          logs.map((log, index) => (
            <div key={index} className={`log-entry ${getLogClass(log.type)}`}>
              <span className="log-time">[{formatTime()}]</span>
              <span className="log-device">[{log.device_name}]</span>
              <span className="log-text">{log.text}</span>
            </div>
          ))
        )}

        {/* Animated cursor */}
        <div className="cursor-wrapper">
          <span className="cursor">_</span>
        </div>
      </div>

      {/* Log count info */}
      <div className="terminal-footer">
        <span className="log-count">
          {logs.length} log{logs.length !== 1 ? 's' : ''} (max 100)
        </span>
      </div>
    </div>
  );
};

export default TaskTerminal;
