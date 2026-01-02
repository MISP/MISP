/**
 * Beta Events Timestamp Utilities
 * 
 * Provides relative timestamp display and click-to-copy functionality
 * for the beta events index table.
 */

(function() {
    'use strict';

    /**
     * Convert Unix timestamp to relative time string
     * @param {number} timestamp - Unix timestamp in seconds
     * @returns {string} Relative time string (e.g., "5m ago", "2d ago")
     */
    function getRelativeTime(timestamp) {
        const now = Math.floor(Date.now() / 1000);
        const diff = now - timestamp;
        
        // Future timestamps
        if (diff < 0) {
            return 'in the future';
        }
        
        // Less than a minute
        if (diff < 60) {
            return diff + 's ago';
        }
        
        // Less than an hour
        if (diff < 3600) {
            const minutes = Math.floor(diff / 60);
            return minutes + 'm ago';
        }
        
        // Less than a day
        if (diff < 86400) {
            const hours = Math.floor(diff / 3600);
            return hours + 'h ago';
        }
        
        // Less than a week
        if (diff < 604800) {
            const days = Math.floor(diff / 86400);
            return days + 'd ago';
        }
        
        // Less than a month (30 days)
        if (diff < 2592000) {
            const weeks = Math.floor(diff / 604800);
            return weeks + 'w ago';
        }
        
        // Less than a year
        if (diff < 31536000) {
            const months = Math.floor(diff / 2592000);
            return months + 'mo ago';
        }
        
        // Years
        const years = Math.floor(diff / 31536000);
        return years + 'y ago';
    }

    /**
     * Copy text to clipboard
     * @param {string} text - Text to copy
     * @returns {Promise<boolean>} Success status
     */
    function copyToClipboard(text) {
        // Modern clipboard API
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text)
                .then(() => true)
                .catch(() => false);
        }
        
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            const successful = document.execCommand('copy');
            document.body.removeChild(textArea);
            return Promise.resolve(successful);
        } catch (err) {
            document.body.removeChild(textArea);
            return Promise.resolve(false);
        }
    }

    /**
     * Show notification message
     * @param {string} message - Message to display
     * @param {string} type - Notification type ('success' or 'error')
     */
    function showNotification(message, type) {
        // Try to use existing MISP notification system if available
        if (typeof showMessage === 'function') {
            showMessage(type === 'success' ? 'success' : 'fail', message);
            return;
        }
        
        // Fallback: Create a simple toast notification
        const toast = document.createElement('div');
        toast.className = 'beta-timestamp-toast beta-timestamp-toast-' + type;
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            background-color: ${type === 'success' ? '#28a745' : '#dc3545'};
            color: white;
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 10000;
            font-size: 14px;
            font-weight: 500;
            animation: slideInRight 0.3s ease-out;
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => {
                document.body.removeChild(toast);
            }, 300);
        }, 3000);
    }

    /**
     * Update all relative timestamps on the page
     */
    function updateRelativeTimestamps() {
        const timestampCells = document.querySelectorAll('.beta-relative-timestamp');
        
        timestampCells.forEach(cell => {
            const timestamp = parseInt(cell.getAttribute('data-timestamp'), 10);
            if (!isNaN(timestamp)) {
                const relativeTime = getRelativeTime(timestamp);
                cell.textContent = relativeTime;
            }
        });
    }

    /**
     * Initialize timestamp functionality
     */
    function init() {
        // Update timestamps on page load
        updateRelativeTimestamps();
        
        // Update timestamps every minute
        setInterval(updateRelativeTimestamps, 60000);
        
        // Add click handlers for copy functionality
        document.addEventListener('click', function(e) {
            const cell = e.target.closest('.beta-relative-timestamp');
            if (cell) {
                const absoluteTime = cell.getAttribute('data-absolute');
                if (absoluteTime) {
                    copyToClipboard(absoluteTime)
                        .then(success => {
                            if (success) {
                                showNotification('Timestamp copied to clipboard: ' + absoluteTime, 'success');
                            } else {
                                showNotification('Failed to copy timestamp', 'error');
                            }
                        });
                }
            }
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Add CSS animations if not already present
    if (!document.getElementById('beta-timestamp-animations')) {
        const style = document.createElement('style');
        style.id = 'beta-timestamp-animations';
        style.textContent = `
            @keyframes slideInRight {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            @keyframes slideOutRight {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(100%);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }
})();
