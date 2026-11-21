// Vigilance Alpine.js Components

// Global utility functions
window.Vigilance = {
    formatDate(dateStr) {
        if (!dateStr) return 'N/A';
        return new Date(dateStr).toLocaleString();
    },

    getSeverityClass(severity) {
        const classes = {
            CRITICAL: 'badge-critical',
            HIGH: 'badge-high',
            MEDIUM: 'badge-medium',
            LOW: 'badge-low',
            NONE: 'badge-none',
        };
        return classes[severity] || classes.NONE;
    },

    getStatusClass(status) {
        const classes = {
            open: 'badge-open',
            fixed: 'badge-fixed',
            suppressed: 'badge-suppressed',
            unknown_version: 'badge-unknown',
        };
        return classes[status] || classes.open;
    },

    async apiGet(url) {
        const resp = await fetch(url);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return resp.json();
    },

    async apiPost(url, data) {
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return resp.json();
    },

    async apiPatch(url, data) {
        const resp = await fetch(url, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return resp.json();
    },

    async apiDelete(url) {
        const resp = await fetch(url, { method: 'DELETE' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return resp.json();
    },

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    },

    confirm(message) {
        return window.confirm(message);
    },
};

// Alpine.js component for auto-refreshing data
document.addEventListener('alpine:init', () => {
    Alpine.data('autoRefresh', (intervalMs = 30000) => ({
        intervalId: null,
        init() {
            this.intervalId = setInterval(() => {
                if (this.$data.loadData) {
                    this.$data.loadData();
                }
            }, intervalMs);
        },
        destroy() {
            if (this.intervalId) clearInterval(this.intervalId);
        },
    }));

    // Component for handling forms with loading states
    Alpine.data('formHandler', () => ({
        submitting: false,
        async submit(formEl, onSuccess, onError) {
            this.submitting = true;
            try {
                const formData = new FormData(formEl);
                const data = Object.fromEntries(formData);
                await onSuccess(data);
            } catch (e) {
                if (onError) onError(e);
                else Vigilance.showToast('Error: ' + e.message, 'error');
            } finally {
                this.submitting = false;
            }
        },
    }));

    // Component for modal management
    Alpine.data('modal', () => ({
        open: false,
        show() { this.open = true; },
        hide() { this.open = false; },
        toggle() { this.open = !this.open; },
    }));
});