/**
 * Scambait Research Suite - Main Application JavaScript
 */

// =============================================================================
// Utility Functions
// =============================================================================

function formatDuration(seconds) {
    if (!seconds || seconds === 0) return '0m';

    if (seconds < 60) {
        return `${seconds}s`;
    } else if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    }
}

function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;

    // Less than 24 hours
    if (diff < 86400000) {
        if (diff < 3600000) {
            const mins = Math.floor(diff / 60000);
            return mins <= 1 ? 'Just now' : `${mins} minutes ago`;
        }
        const hours = Math.floor(diff / 3600000);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }

    // Less than 7 days
    if (diff < 604800000) {
        const days = Math.floor(diff / 86400000);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }

    // Format as date
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
    });
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// =============================================================================
// Toast Notifications
// =============================================================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    // Auto-remove after 4 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// =============================================================================
// Modal Functions
// =============================================================================

function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
    }
}

function showNewSessionModal() {
    showModal('new-session-modal');
}

// =============================================================================
// Session Management
// =============================================================================

async function createSession(event) {
    event.preventDefault();

    const title = document.getElementById('session-title').value;
    const scamType = document.getElementById('scam-type').value;
    const source = document.getElementById('source').value;
    const scriptId = document.getElementById('script-id').value;
    const notes = document.getElementById('notes').value;

    const sessionData = {
        title: title || null,
        scam_type: scamType || null,
        source: source || null,
        script_id: scriptId || null,
        notes: notes || null
    };

    try {
        const response = await fetch('/api/sessions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(sessionData)
        });

        if (!response.ok) {
            throw new Error('Failed to create session');
        }

        const session = await response.json();

        showToast('Session created successfully', 'success');
        closeModal('new-session-modal');

        // Clear form
        document.getElementById('new-session-form').reset();

        // Redirect to session page
        window.location.href = `/session/${session.id}`;

    } catch (error) {
        showToast('Failed to create session: ' + error.message, 'error');
    }
}

// =============================================================================
// Page Refresh
// =============================================================================

function refreshPage() {
    location.reload();
}

// =============================================================================
// API Helpers
// =============================================================================

async function apiCall(endpoint, method = 'GET', body = null) {
    const options = {
        method,
        headers: {}
    };

    if (body) {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }

    const response = await fetch(endpoint, options);

    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.detail || `API Error: ${response.status}`);
    }

    return response.json();
}

// =============================================================================
// Keyboard Shortcuts
// =============================================================================

document.addEventListener('keydown', (e) => {
    // Escape closes modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.active').forEach(modal => {
            modal.classList.remove('active');
        });
    }

    // Ctrl+N opens new session modal
    if (e.ctrlKey && e.key === 'n') {
        e.preventDefault();
        showNewSessionModal();
    }

    // Ctrl+R refreshes (let browser handle it)
});

// =============================================================================
// Initialize
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('Scambait Research Suite initialized');

    // Check health
    fetch('/api/health')
        .then(r => r.json())
        .then(data => {
            console.log('API Status:', data.status);
        })
        .catch(err => {
            console.error('API Health Check Failed:', err);
            showToast('Warning: API connection issues', 'error');
        });
});
