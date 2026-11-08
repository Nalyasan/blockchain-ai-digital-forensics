// dashboard/static/js/main.js - Blockchain Ai Aigital Forensics Interactivity

function switchCase(caseId) {
  if (!caseId) return;
  const url = new URL(window.location.href);
  url.searchParams.set('case_id', caseId);
  url.searchParams.delete('run_id');
  window.location.href = url.toString();
}

function switchRun(runId) {
  if (!runId) return;
  const url = new URL(window.location.href);
  url.searchParams.set('run_id', runId);
  if (url.pathname.startsWith('/progress/')) {
    url.pathname = '/progress/' + runId;
    url.search = '';
  } else if (url.pathname.startsWith('/reports/')) {
    url.pathname = '/reports/' + runId;
    url.search = '';
  }
  window.location.href = url.toString();
}

document.addEventListener('DOMContentLoaded', () => {
  // 1. Live UTC Clock
  const clockEl = document.getElementById('clock-utc');
  function updateClock() {
    if (clockEl) {
      const now = new Date();
      clockEl.textContent = now.toISOString().substring(11, 19);
    }
  }
  updateClock();
  setInterval(updateClock, 1000);

  // 2. Poll global system status to update sidebar badge
  const statusBadge = document.getElementById('global-status-badge');
  async function checkSystemStatus() {
    if (!statusBadge) return;
    try {
      const res = await fetch('/api/system/status');
      if (res.ok) {
        const data = await res.json();
        if (data.is_busy) {
          statusBadge.textContent = 'Đang xử lý';
          statusBadge.className = 'px-2 py-0.5 rounded text-[11px] font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800 animate-pulse';
        } else {
          statusBadge.textContent = 'Sẵn sàng';
          statusBadge.className = 'px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800';
        }
      }
    } catch (e) {
      // Quietly ignore network failures in background
    }
  }

  checkSystemStatus();
  setInterval(checkSystemStatus, 5000);
});
