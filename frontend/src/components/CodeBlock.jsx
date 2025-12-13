import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

/**
 * CodeBlock component with syntax highlighting and copy-to-clipboard functionality
 * @param {string} code - The code/query to display
 * @param {string} language - The language/platform identifier
 * @param {string} description - Optional description of the code
 */
export default function CodeBlock({ code, language, description }) {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(code);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    return (
        <div className="code-block-container">
            <div className="code-block-header">
                <div className="code-platform-badge">{language}</div>
                <button
                    className="copy-button"
                    onClick={handleCopy}
                    title="Copy to clipboard"
                >
                    {copied ? (
                        <>
                            <Check size={14} />
                            <span>Copied!</span>
                        </>
                    ) : (
                        <>
                            <Copy size={14} />
                            <span>Copy</span>
                        </>
                    )}
                </button>
            </div>

            {description && (
                <div className="code-description">
                    {description}
                </div>
            )}

            <pre className="code-block">
                <code>{code}</code>
            </pre>
        </div>
    );
}
