/**
 * Scambait Research Suite - Timeline Functions
 */

// =============================================================================
// Timeline Rendering
// =============================================================================

function renderTimelineMessage(message, index) {
    const isInbound = message.direction === 'inbound';

    return `
        <div class="timeline-item ${message.direction}" data-id="${message.id}" data-index="${index}">
            <div class="timeline-marker"></div>
            <div class="timeline-content">
                <div class="timeline-header">
                    <span class="direction-badge ${message.direction}">
                        ${isInbound ? '📥 Scammer' : '📤 You'}
                    </span>
                    <span class="timestamp">${formatMessageTime(message.timestamp)}</span>
                    ${message.delay_applied_seconds > 0 ?
                        `<span class="delay-badge">⏱️ +${message.delay_applied_seconds}s delay</span>` : ''}
                </div>
                <div class="message-text">${formatMessageContent(message.content)}</div>
                ${message.content_type !== 'text' ?
                    `<div class="content-type-badge">${message.content_type}</div>` : ''}
            </div>
        </div>
    `;
}

function formatMessageTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();

    if (isToday) {
        return date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatMessageContent(content) {
    // Escape HTML
    let formatted = content
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');

    // Detect and defang URLs
    formatted = formatted.replace(
        /(https?:\/\/[^\s]+)/gi,
        '<span class="detected-url" title="URL detected - defanged for safety">🔗 $1</span>'
    );

    // Detect phone numbers
    formatted = formatted.replace(
        /(\b\d{3}[-.]?\d{3}[-.]?\d{4}\b)/g,
        '<span class="detected-phone" title="Phone number detected">📞 $1</span>'
    );

    // Detect email addresses
    formatted = formatted.replace(
        /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
        '<span class="detected-email" title="Email detected">📧 $1</span>'
    );

    // Detect money amounts
    formatted = formatted.replace(
        /(\$[\d,]+(?:\.\d{2})?|\d+\s*(?:btc|eth|sol|usd|dollars?))/gi,
        '<span class="detected-money" title="Money amount detected">💰 $1</span>'
    );

    // Preserve newlines
    formatted = formatted.replace(/\n/g, '<br>');

    return formatted;
}

// =============================================================================
// Auto-scroll
// =============================================================================

function scrollTimelineToBottom() {
    const container = document.getElementById('timeline');
    if (container) {
        container.scrollTop = container.scrollHeight;
    }
}

// =============================================================================
// Message Highlighting
// =============================================================================

function highlightMessage(messageId) {
    // Remove existing highlights
    document.querySelectorAll('.timeline-item.highlighted').forEach(el => {
        el.classList.remove('highlighted');
    });

    // Add highlight to target
    const target = document.querySelector(`.timeline-item[data-id="${messageId}"]`);
    if (target) {
        target.classList.add('highlighted');
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

// =============================================================================
// Real-time Updates (Polling)
// =============================================================================

let pollInterval = null;
let lastMessageCount = 0;

function startTimelinePolling(sessionId, intervalMs = 5000) {
    if (pollInterval) {
        clearInterval(pollInterval);
    }

    pollInterval = setInterval(async () => {
        try {
            const response = await fetch(`/api/sessions/${sessionId}/messages`);
            const messages = await response.json();

            if (messages.length > lastMessageCount) {
                // New messages arrived
                lastMessageCount = messages.length;

                // Re-render timeline
                const container = document.getElementById('timeline');
                if (container) {
                    container.innerHTML = messages.map((msg, i) => renderTimelineMessage(msg, i)).join('');
                    scrollTimelineToBottom();

                    // Show notification
                    showToast(`${messages.length - lastMessageCount + 1} new message(s)`, 'info');
                }
            }
        } catch (error) {
            console.error('Polling error:', error);
        }
    }, intervalMs);
}

function stopTimelinePolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
}

// =============================================================================
// Export Functions
// =============================================================================

function exportTimeline(messages, format = 'text') {
    if (format === 'text') {
        let output = 'SCAMBAIT SESSION TRANSCRIPT\n';
        output += '='.repeat(50) + '\n\n';

        messages.forEach(msg => {
            const direction = msg.direction === 'inbound' ? 'SCAMMER' : 'RESEARCHER';
            const time = new Date(msg.timestamp).toLocaleString();
            output += `[${time}] ${direction}:\n`;
            output += msg.content + '\n\n';
        });

        return output;
    }

    if (format === 'json') {
        return JSON.stringify(messages, null, 2);
    }

    return '';
}

// =============================================================================
// Timeline Statistics
// =============================================================================

function calculateTimelineStats(messages) {
    const stats = {
        totalMessages: messages.length,
        inboundCount: 0,
        outboundCount: 0,
        totalDelay: 0,
        avgResponseTime: 0,
        longestMessage: 0,
        firstMessage: null,
        lastMessage: null
    };

    if (messages.length === 0) return stats;

    let responseTimes = [];
    let lastOutbound = null;

    messages.forEach((msg, i) => {
        if (msg.direction === 'inbound') {
            stats.inboundCount++;
            if (lastOutbound) {
                const responseTime = new Date(msg.timestamp) - new Date(lastOutbound.timestamp);
                if (responseTime > 0) {
                    responseTimes.push(responseTime / 1000);
                }
            }
        } else {
            stats.outboundCount++;
            lastOutbound = msg;
        }

        stats.totalDelay += msg.delay_applied_seconds || 0;

        if (msg.content.length > stats.longestMessage) {
            stats.longestMessage = msg.content.length;
        }
    });

    stats.firstMessage = messages[0].timestamp;
    stats.lastMessage = messages[messages.length - 1].timestamp;

    if (responseTimes.length > 0) {
        stats.avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    }

    return stats;
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    stopTimelinePolling();
});
