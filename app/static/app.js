const state = {
  accessToken: "",
  refreshToken: "",
  fingerprint: `web-${Math.random().toString(36).slice(2, 12)}`,
};

const output = document.getElementById("output");
const tokenPreview = document.getElementById("tokenPreview");
const fpPreview = document.getElementById("fpPreview");

function log(title, payload) {
  const stamp = new Date().toLocaleTimeString();
  const body = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  output.textContent = `[${stamp}] ${title}\n${body}\n\n` + output.textContent;
}

function updateSessionPreview() {
  tokenPreview.textContent = state.accessToken ? `${state.accessToken.slice(0, 28)}...` : "No token";
  fpPreview.textContent = state.fingerprint || "Not set";
  const enabled = Boolean(state.accessToken);
  document.getElementById("processBtn").disabled = !enabled;
  document.getElementById("myReputationBtn").disabled = !enabled;
}

function headers(useAuth = false, useAdminKey = false) {
  const h = { "Content-Type": "application/json" };
  if (state.fingerprint) {
    h["X-Device-Fingerprint"] = state.fingerprint;
  }
  if (useAuth && state.accessToken) {
    h.Authorization = `Bearer ${state.accessToken}`;
  }
  if (useAdminKey) {
    const key = document.querySelector('#adminForm input[name="admin_key"]').value.trim();
    if (key) h["X-Admin-Key"] = key;
  }
  return h;
}

async function callApi(title, url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({ message: "non-json response" }));
  log(`${title} (${res.status})`, { data, headers: Object.fromEntries(res.headers.entries()) });
  return { res, data };
}

document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await callApi("Register", "/auth/register", {
    method: "POST",
    headers: headers(false),
    body: JSON.stringify({
      email: fd.get("email"),
      password: fd.get("password"),
    }),
  });
});

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const { data } = await callApi("Login", "/auth/login", {
    method: "POST",
    headers: headers(false),
    body: JSON.stringify({
      email: fd.get("email"),
      password: fd.get("password"),
    }),
  });
  if (data.access_token) {
    state.accessToken = data.access_token;
    state.refreshToken = data.refresh_token || "";
    updateSessionPreview();
  }
});

document.getElementById("processForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await callApi("Process Request", "/api/process", {
    method: "POST",
    headers: headers(true),
    body: JSON.stringify({ seconds: Number(fd.get("seconds")) }),
  });
});

document.getElementById("myReputationBtn").addEventListener("click", async () => {
  await callApi("My Reputation", "/api/reputation/me", {
    method: "GET",
    headers: headers(true),
  });
});

document.getElementById("summaryBtn").addEventListener("click", async () => {
  await callApi("Admin Summary", "/admin/reputation/summary", {
    method: "GET",
    headers: headers(false, true),
  });
});

document.getElementById("blockedBtn").addEventListener("click", async () => {
  await callApi("Blocked Users", "/admin/reputation/blocked-users", {
    method: "GET",
    headers: headers(false, true),
  });
});

document.getElementById("eventsBtn").addEventListener("click", async () => {
  await callApi("Recent Events", "/admin/reputation/events?limit=20", {
    method: "GET",
    headers: headers(false, true),
  });
});

document.getElementById("unblockBtn").addEventListener("click", async () => {
  const userId = document.querySelector('#adminForm input[name="unblock_user_id"]').value;
  if (!userId) {
    log("Unblock User", "Provide a user id first.");
    return;
  }
  await callApi("Unblock User", `/admin/reputation/users/${userId}/unblock`, {
    method: "POST",
    headers: headers(false, true),
  });
});

updateSessionPreview();
