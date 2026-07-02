/**
 * Scambait Research Suite - Chart Functions
 * Uses simple canvas-based charts (no external dependencies)
 */

// =============================================================================
// Simple Pie Chart
// =============================================================================

function drawPieChart(canvasId, data, colors) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 40;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Calculate total
    const total = Object.values(data).reduce((a, b) => a + b, 0);

    if (total === 0) {
        // Draw empty state
        ctx.fillStyle = '#334155';
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
        ctx.fill();

        ctx.fillStyle = '#64748b';
        ctx.font = '14px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No data', centerX, centerY);
        return;
    }

    // Draw slices
    let startAngle = -Math.PI / 2;
    const entries = Object.entries(data);

    entries.forEach(([label, value], index) => {
        const sliceAngle = (value / total) * 2 * Math.PI;

        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        ctx.closePath();

        ctx.fillStyle = colors[index % colors.length];
        ctx.fill();

        // Draw label if slice is big enough
        if (sliceAngle > 0.3) {
            const labelAngle = startAngle + sliceAngle / 2;
            const labelX = centerX + (radius * 0.6) * Math.cos(labelAngle);
            const labelY = centerY + (radius * 0.6) * Math.sin(labelAngle);

            ctx.fillStyle = '#ffffff';
            ctx.font = '12px Inter, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(label, labelX, labelY);
        }

        startAngle += sliceAngle;
    });

    // Draw legend
    const legendY = canvas.height - 20;
    let legendX = 20;

    entries.forEach(([label, value], index) => {
        ctx.fillStyle = colors[index % colors.length];
        ctx.fillRect(legendX, legendY - 10, 12, 12);

        ctx.fillStyle = '#94a3b8';
        ctx.font = '11px Inter, sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText(`${label}: ${value}`, legendX + 16, legendY);

        legendX += ctx.measureText(`${label}: ${value}`).width + 30;
    });
}

// =============================================================================
// Simple Bar Chart
// =============================================================================

function drawBarChart(canvasId, data, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const padding = { top: 20, right: 20, bottom: 60, left: 50 };

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const chartWidth = canvas.width - padding.left - padding.right;
    const chartHeight = canvas.height - padding.top - padding.bottom;

    const entries = Object.entries(data);

    if (entries.length === 0) {
        ctx.fillStyle = '#64748b';
        ctx.font = '14px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No data', canvas.width / 2, canvas.height / 2);
        return;
    }

    const maxValue = Math.max(...Object.values(data), 1);
    const barWidth = (chartWidth / entries.length) * 0.7;
    const gap = (chartWidth / entries.length) * 0.3;

    // Draw bars
    entries.forEach(([label, value], index) => {
        const barHeight = (value / maxValue) * chartHeight;
        const x = padding.left + index * (barWidth + gap) + gap / 2;
        const y = padding.top + chartHeight - barHeight;

        // Bar
        ctx.fillStyle = color || '#3b82f6';
        ctx.fillRect(x, y, barWidth, barHeight);

        // Value on top
        ctx.fillStyle = '#f8fafc';
        ctx.font = '12px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(value, x + barWidth / 2, y - 5);

        // Label below
        ctx.fillStyle = '#94a3b8';
        ctx.font = '11px Inter, sans-serif';
        ctx.save();
        ctx.translate(x + barWidth / 2, canvas.height - padding.bottom + 15);
        ctx.rotate(-Math.PI / 4);
        ctx.textAlign = 'right';
        ctx.fillText(label.substring(0, 10), 0, 0);
        ctx.restore();
    });

    // Y axis
    ctx.strokeStyle = '#334155';
    ctx.beginPath();
    ctx.moveTo(padding.left, padding.top);
    ctx.lineTo(padding.left, canvas.height - padding.bottom);
    ctx.stroke();
}

// =============================================================================
// Chart Update Functions
// =============================================================================

const chartColors = [
    '#3b82f6', '#8b5cf6', '#22c55e', '#f59e0b',
    '#ef4444', '#06b6d4', '#ec4899', '#84cc16'
];

function updateScamTypesChart(data) {
    const canvas = document.getElementById('scam-types-chart');
    if (!canvas) return;

    // Set canvas size
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = 250;

    drawPieChart('scam-types-chart', data, chartColors);
}

function updatePatternsChart(data) {
    const canvas = document.getElementById('patterns-chart');
    if (!canvas) return;

    // Set canvas size
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = 250;

    drawBarChart('patterns-chart', data, '#8b5cf6');
}

// =============================================================================
// Resize Handler
// =============================================================================

let resizeTimeout;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
        // Re-fetch and redraw charts
        if (typeof loadStats === 'function') {
            loadStats();
        }
    }, 250);
});
