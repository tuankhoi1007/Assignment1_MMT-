// Client-side UI Controller for Assignment 1 & CO3094
let currentChannel = "ALL";
let isConnected = false;
let selectedFile = null;
let lastSeenMsgCount = 0;
const unreadCounts = {};

// Periodic polling every 1 second
document.addEventListener("DOMContentLoaded", () => {
  fetchState();
  setInterval(fetchState, 1000);
});

window.onfocus = () => {
  delete unreadCounts[currentChannel];
  refreshTabTitle();
  fetchState();
};

function refreshTabTitle() {
  const total = Object.values(unreadCounts).reduce((a, b) => a + b, 0);
  if (total > 0) {
    document.title = `(${total}) Assignment 1 - Distributed Streaming Collaboration System`;
  } else {
    document.title = "Assignment 1 - Distributed Streaming Collaboration System";
  }
}

function updateNotifications(messages, myUsername) {
  if (!messages || !Array.isArray(messages)) return;
  if (messages.length > lastSeenMsgCount && lastSeenMsgCount > 0) {
    const newMsgs = messages.slice(lastSeenMsgCount);
    newMsgs.forEach(m => {
      if (!m.is_mine && myUsername && m.sender !== myUsername) {
        const ch = m.is_broadcast ? "ALL" : m.sender;
        if (ch !== currentChannel) {
          unreadCounts[ch] = (unreadCounts[ch] || 0) + 1;
        }
      }
    });
    refreshTabTitle();
  }
  lastSeenMsgCount = messages.length;
}

// Toggle Connection Modal
function toggleConnectModal() {
  const modal = document.getElementById("modal-connect");
  modal.classList.toggle("hidden");
  if (!modal.classList.contains("hidden")) {
    document.getElementById("input-username").focus();
  }
}

// Connect to Server using Username, Host IP, and Port
async function connectToServer() {
  const username = document.getElementById("input-username").value.trim();
  const host = (document.getElementById("input-host")?.value || "127.0.0.1").trim();
  const port = parseInt(document.getElementById("input-port")?.value || "8888", 10);
  const password = document.getElementById("input-password")?.value || "";
  const register = document.getElementById("input-register")?.checked || false;

  if (!username) return alert("Please enter username!");
  if (register && password.length < 4) return alert("Password must be at least 4 characters to register!");

  try {
    const res = await fetch("/api/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, host, port, password, register })
    });
    const data = await res.json();
    if (data.success) {
      toggleConnectModal();
      fetchState();
    } else {
      alert("Connect failed: " + data.message);
    }
  } catch (err) {
    alert("Error connecting: " + err);
  }
}

// Disconnect from Server
async function disconnectFromServer() {
  try {
    await fetch("/api/disconnect", { method: "POST" });
    for (const k in unreadCounts) delete unreadCounts[k];
    lastSeenMsgCount = 0;
    refreshTabTitle();
    fetchState();
  } catch (err) {
    console.error(err);
  }
}

// Fetch Client State (Peers, Messages, Transfers)
async function fetchState() {
  try {
    const res = await fetch("/api/state");
    const s = await res.json();

    isConnected = s.is_connected;
    updateNotifications(s.messages, s.username);
    updateHeader(s);
    updatePeers(s.active_users, s.username);
    renderMessages(s.messages, s.username);
    renderTransfers(s.transfers);
  } catch (err) {
    console.warn("State fetch error:", err);
  }
}

// Update Top Navigation Bar
function updateHeader(s) {
  const ind = document.getElementById("status-indicator");
  const txt = document.getElementById("status-text");
  const chip = document.getElementById("current-user-info");
  const btn = document.getElementById("btn-toggle-connect");

  if (s.is_connected) {
    ind.className = "status-indicator connected";
    txt.textContent = "Online";
    chip.classList.remove("hidden");
    document.getElementById("my-avatar").textContent = (s.username || "U")[0].toUpperCase();
    document.getElementById("my-username").textContent = s.username + (s.guest ? " (guest)" : "");
    const badge = document.getElementById("my-udp-port");
    badge.textContent = "UDP: " + s.udp_port;
    badge.title = s.fingerprint ? ("Key fingerprint: " + s.fingerprint) : "";
    btn.textContent = "Disconnect";
    btn.className = "btn btn-secondary";
    btn.onclick = disconnectFromServer;
  } else {
    ind.className = "status-indicator disconnected";
    txt.textContent = "Disconnected";
    chip.classList.add("hidden");
    btn.textContent = "Connect";
    btn.className = "btn btn-primary";
    btn.onclick = toggleConnectModal;
  }
}

// Update Sidebar Peers and Recipient Select
function updatePeers(peers, myUsername) {
  const container = document.getElementById("peers-container");
  const select = document.getElementById("file-target-select");
  const unreadGlobal = document.getElementById("unread-global");
  const others = (peers || []).filter(p => p.username !== myUsername);

  document.getElementById("user-count").textContent = (peers || []).length;

  if (unreadGlobal) {
    const gCount = unreadCounts["ALL"] || 0;
    if (gCount > 0) {
      unreadGlobal.textContent = gCount > 99 ? "99+" : gCount;
      unreadGlobal.classList.remove("hidden");
    } else {
      unreadGlobal.classList.add("hidden");
    }
  }

  if (others.length === 0) {
    container.innerHTML = '<div class="empty-hint">No other peers online</div>';
  } else {
    container.innerHTML = others.map(p => {
      const pCount = unreadCounts[p.username] || 0;
      const badge = pCount > 0 ? `<span class="unread-badge">${pCount > 99 ? '99+' : pCount}</span>` : '';
      return `
        <div class="peer-item ${currentChannel === p.username ? 'active' : ''}" onclick="selectChannel('${escapeHtml(p.username)}')" ${p.fingerprint ? `title="Key ${escapeHtml(p.fingerprint)}"` : ""}>
          <span class="avatar">${escapeHtml(p.username[0].toUpperCase())}</span>
          <div class="peer-meta">
            <span class="peer-name">${escapeHtml(p.username)}</span>
            <span class="peer-status">${p.ip}:${p.udp_port}</span>
          </div>
          ${badge}
        </div>
      `;
    }).join("");
  }

  const currentVal = select.value;
  select.innerHTML = '<option value="">Select a peer...</option>' +
    others.map(p => `<option value="${escapeHtml(p.username)}">${escapeHtml(p.username)} (${p.ip}:${p.udp_port})</option>`).join("");
  if (currentVal && others.some(p => p.username === currentVal)) select.value = currentVal;
}

// Switch between Global Chat and Direct Peer Chat
function selectChannel(ch) {
  currentChannel = ch;
  delete unreadCounts[ch];
  refreshTabTitle();
  document.getElementById("channel-global").className = "channel-item" + (ch === "ALL" ? " active" : "");
  document.getElementById("chat-header-icon").textContent = ch === "ALL" ? "🌐" : "💬";
  document.getElementById("chat-target-name").textContent = ch === "ALL" ? "Global Chat" : "@" + ch;
  fetchState();
}

// Render Messages for Current Channel
function renderMessages(messages, myUsername) {
  const vp = document.getElementById("messages-viewport");
  const filtered = (messages || []).filter(m =>
    currentChannel === "ALL" ? m.is_broadcast :
    (!m.is_broadcast && ((m.sender === currentChannel && m.target === myUsername) || (m.sender === myUsername && m.target === currentChannel)))
  );

  if (filtered.length === 0) {
    vp.innerHTML = `<div class="message-notice">No messages in ${currentChannel === "ALL" ? "Global Chat" : "@" + currentChannel} yet.</div>`;
    return;
  }

  const shouldScroll = vp.scrollTop + vp.clientHeight >= vp.scrollHeight - 60;
  vp.innerHTML = filtered.map(m => {
    const isMine = m.sender === myUsername;
    const time = new Date((m.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    return `
      <div class="chat-bubble ${isMine ? 'mine' : 'other'}">
        <div class="bubble-meta"><span>${escapeHtml(m.sender)}</span> • <span>${time}</span></div>
        <div class="bubble-content">${escapeHtml(m.text)}</div>
      </div>
    `;
  }).join("");

  if (shouldScroll) vp.scrollTop = vp.scrollHeight;
}

// Send Message
async function sendMessage() {
  const input = document.getElementById("input-message");
  const text = input.value.trim();
  if (!text) return;
  if (!isConnected) return alert("Please connect to server first!");

  input.value = "";
  try {
    await fetch("/api/send_message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: currentChannel, text })
    });
    fetchState();
  } catch (err) {
    console.error("Send error:", err);
  }
}

function handleChatKey(e) {
  if (e.key === "Enter") sendMessage();
}

// File Selection
function handleFileSelected(e) {
  selectedFile = e.target.files[0];
  const box = document.getElementById("file-picker-box");
  const label = document.getElementById("file-picker-label");
  const btn = document.getElementById("btn-send-file");

  if (selectedFile) {
    if (box) box.classList.add("selected");
    if (label) label.textContent = `${selectedFile.name} (${formatBytes(selectedFile.size)})`;
    btn.disabled = false;
  } else {
    if (box) box.classList.remove("selected");
    if (label) label.textContent = "Click to select file";
    btn.disabled = true;
  }
}

// Upload & Stream File over UDP
async function uploadAndSendFile() {
  const target = document.getElementById("file-target-select").value;
  if (!target) return alert("Please choose recipient peer!");
  if (!selectedFile) return alert("Please select a file!");

  const btn = document.getElementById("btn-send-file");
  btn.disabled = true;
  btn.textContent = "Streaming over UDP...";

  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const res = await fetch("/api/upload_and_send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          filename: selectedFile.name,
          content_b64: reader.result.split(",")[1],
          force_relay: document.getElementById("force-relay")?.checked || false
        })
      });
      const data = await res.json();
      if (!data.success) alert("Transfer failed: " + data.message);
    } catch (err) {
      alert("Streaming error: " + err);
    } finally {
      btn.textContent = "Start UDP Streaming Transfer";
      btn.disabled = false;
      fetchState();
    }
  };
  reader.readAsDataURL(selectedFile);
}

// Render UDP Transfers
function renderTransfers(transfers) {
  const container = document.getElementById("transfers-container");
  const list = transfers || [];
  if (list.length === 0) {
    container.innerHTML = '<div class="empty-hint">No active transfers</div>';
    return;
  }

  container.innerHTML = list.map(t => {
    const isDone = t.progress >= 100;
    const roleIcon = t.role === "sender" ? "⬆" : "⬇";
    const via = t.path === "relay" ? "relay" : (t.path === "direct" ? "direct" : "");
    const cwnd = t.cwnd != null ? `cwnd ${t.cwnd}` : "";
    const extra = [via, cwnd].filter(Boolean).join(" · ");
    const status = (isDone ? "Completed" : (t.role === "sender" ? "Sending..." : "Receiving...")) + (extra ? ` (${extra})` : "");
    const downloadName = t.saved_filename || t.filename;

    return `
      <div class="transfer-card">
        <div class="transfer-meta">
          <span class="transfer-filename" title="${escapeHtml(t.filename)}">${roleIcon} ${escapeHtml(t.filename)}</span>
          <span class="transfer-pct">${t.progress}%</span>
        </div>
        <div class="progress-track"><div class="progress-bar" style="width: ${t.progress}%;"></div></div>
        <div class="transfer-footer">
          <span>${status} ${isDone && t.role === "receiver" ? `<a href="/downloads/${encodeURIComponent(downloadName)}" target="_blank" class="download-link">Open</a>` : ''}</span>
          <span>${formatBytes(t.file_size)}</span>
        </div>
      </div>
    `;
  }).join("");
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const k = 1024, sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(1) + " " + sizes[i];
}

function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text || "").replace(/[&<>"']/g, m => map[m]);
}
