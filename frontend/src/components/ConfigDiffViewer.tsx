import React, { useState } from 'react';
import { DiffEditor } from '@monaco-editor/react';
import { useTheme } from '../contexts/ThemeContext';
import '../styles/ConfigViewer.css';

interface ConfigDiffViewerProps {
  originalConfig: string;
  modifiedConfig: string;
  originalTitle?: string;
  modifiedTitle?: string;
  onClose?: () => void;
}

const ConfigDiffViewer: React.FC<ConfigDiffViewerProps> = ({
  originalConfig,
  modifiedConfig,
  originalTitle = 'Original',
  modifiedTitle = 'Modified',
  onClose
}) => {
  const { theme } = useTheme();
  const [renderSideBySide, setRenderSideBySide] = useState(true);
  const editorRef = React.useRef<any>(null);

  // Map our theme to Monaco theme
  const getMonacoTheme = () => {
    if (theme === 'industrial' || theme === 'neumorphism') {
      return 'light';
    }
    return 'vs-dark';
  };

  const handleEditorMount = (editor: any) => {
    editorRef.current = editor;
    // Manual layout on mount
    setTimeout(() => {
      editor?.layout();
    }, 100);
  };

  const handleSearch = () => {
    if (editorRef.current) {
      editorRef.current.getModifiedEditor().trigger('', 'actions.find');
    }
  };

  const toggleViewMode = () => {
    setRenderSideBySide(prev => !prev);
  };

  const handleDownloadDiff = () => {
    const diffText = `=== DIFF COMPARISON ===
Original: ${originalTitle}
Modified: ${modifiedTitle}
Generated: ${new Date().toISOString()}

=== ORIGINAL ===
${originalConfig}

=== MODIFIED ===
${modifiedConfig}
`;
    const blob = new Blob([diffText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `config_diff_${new Date().getTime()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="config-viewer config-diff-viewer">
      <div className="config-viewer-header">
        <h3>Configuration Diff: {originalTitle} ↔ {modifiedTitle}</h3>
        <div className="config-viewer-actions">
          <button onClick={handleSearch} className="btn-icon" title="Search (Ctrl+F)">
            🔍
          </button>
          <button
            onClick={toggleViewMode}
            className="btn-icon"
            title={renderSideBySide ? 'Switch to Inline View' : 'Switch to Side-by-Side View'}
          >
            {renderSideBySide ? '⬌' : '⬍'}
          </button>
          <button onClick={handleDownloadDiff} className="btn-icon" title="Download Diff">
            ⬇️
          </button>
          {onClose && (
            <button onClick={onClose} className="btn-icon" title="Close">
              ✕
            </button>
          )}
        </div>
      </div>
      <div className="config-viewer-content">
        <DiffEditor
          height="600px"
          original={originalConfig}
          modified={modifiedConfig}
          language="plaintext"
          theme={getMonacoTheme()}
          onMount={handleEditorMount}
          options={{
            readOnly: true,
            renderSideBySide: renderSideBySide,
            enableSplitViewResizing: true,
            renderOverviewRuler: true,
            minimap: { enabled: true },
            fontSize: 14,
            lineNumbers: 'on',
            scrollBeyondLastLine: true,
            automaticLayout: false,
            folding: true,
            renderWhitespace: 'selection',
            padding: { top: 10, bottom: 10 },
            diffWordWrap: 'off',
            ignoreTrimWhitespace: false,
            renderIndicators: true,
            originalEditable: false,
            diffCodeLens: false,
          }}
        />
      </div>
      <div className="config-diff-legend">
        <span className="diff-legend-item">
          <span className="diff-color diff-added"></span> Added
        </span>
        <span className="diff-legend-item">
          <span className="diff-color diff-removed"></span> Removed
        </span>
        <span className="diff-legend-item">
          <span className="diff-color diff-modified"></span> Modified
        </span>
      </div>
    </div>
  );
};

export default ConfigDiffViewer;
