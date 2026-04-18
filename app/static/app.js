const state = {
  accessToken: "",
  refreshToken: "",
  loginIp: "",
  fingerprint: "",
};

const output = document.getElementById("output");
const tokenPreview = document.getElementById("tokenPreview");
const tokenPreviewBottom = document.getElementById("tokenPreviewBottom");
const fpPreview = document.getElementById("fpPreview");
const ipPreview = document.getElementById("ipPreview");

function log(title, payload) {
  const stamp = new Date().toLocaleTimeString();
  const body = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  output.textContent = `[${stamp}] ${title}\n${body}\n\n` + output.textContent;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function shortToken(token) {
  if (!token) return "No token";
  return `${token.slice(0, 28)}...`;
}

function updateSessionPreview() {
  tokenPreview.textContent = shortToken(state.accessToken);
  tokenPreviewBottom.textContent = shortToken(state.accessToken);
  fpPreview.textContent = state.fingerprint || "Not set";
  ipPreview.textContent = state.loginIp || "Not set";

  const enabled = Boolean(state.accessToken);
  document.getElementById("processBtn").disabled = !enabled;
  document.getElementById("myReputationBtn").disabled = !enabled;
  document.getElementById("blockDemoBtn").disabled = !enabled;
}

function adminKeyHeader() {
  const key = document.querySelector('#adminForm input[name="admin_key"]').value.trim();
  return key ? { "X-Admin-Key": key } : {};
}

function validationHeaders(jwt, ip, fingerprint) {
  const headers = {
    "Content-Type": "application/json",
    "X-Forwarded-For": (ip || "").trim(),
    "X-Device-Fingerprint": (fingerprint || "").trim(),
  };

  if (jwt && jwt.trim()) {
    headers.Authorization = `Bearer ${jwt.trim()}`;
  }
  return headers;
}

function getRequestContextFromForm() {
  const form = new FormData(document.getElementById("processForm"));
  return {
    seconds: Number(form.get("seconds")),
    jwt: String(form.get("jwt") || ""),
    ip: String(form.get("ip") || ""),
    fingerprint: String(form.get("fingerprint") || ""),
  };
}

async function callApi(title, url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({ message: "non-json response" }));

  if (res.status === 403 && data && data.error === "context_mismatch") {
    data.message = "Context changed. Login again with correct details.";
  }

  log(`${title} (${res.status})`, { data, headers: Object.fromEntries(res.headers.entries()) });
  return { res, data };
}

document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);

  const fallbackFp = state.fingerprint || `register-${Math.random().toString(36).slice(2, 10)}`;
  const fallbackIp = state.loginIp || "10.20.30.40";

  await callApi("Register", "/auth/register", {
    method: "POST",
    headers: validationHeaders("", fallbackIp, fallbackFp),
    body: JSON.stringify({
      email: fd.get("email"),
      password: fd.get("password"),
    }),
  });
});

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);

  const ip = String(fd.get("ip") || "").trim();
  const fingerprint = String(fd.get("fingerprint") || "").trim();

  const { data } = await callApi("Login", "/auth/login", {
    method: "POST",
    headers: validationHeaders("", ip, fingerprint),
    body: JSON.stringify({
      email: fd.get("email"),
      password: fd.get("password"),
    }),
  });

  if (data.access_token) {
    state.accessToken = data.access_token;
    state.refreshToken = data.refresh_token || "";
    state.loginIp = ip;
    state.fingerprint = fingerprint;

    document.getElementById("jwtInput").value = state.accessToken;
    document.getElementById("ipInput").value = state.loginIp;
    document.getElementById("fpInput").value = state.fingerprint;

    updateSessionPreview();
  }
});

document.getElementById("copyJwtBtn").addEventListener("click", async () => {
  if (!state.accessToken) {
    log("Copy JWT", "No JWT token available. Login first.");
    return;
  }
  try {
    await navigator.clipboard.writeText(state.accessToken);
    log("Copy JWT", "JWT copied to clipboard.");
  } catch {
    log("Copy JWT", "Clipboard not available in this browser context.");
  }
});

document.getElementById("processForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const req = getRequestContextFromForm();

  await callApi("Process Request", "/api/process", {
    method: "POST",
    headers: validationHeaders(req.jwt, req.ip, req.fingerprint),
    body: JSON.stringify({ seconds: req.seconds }),
  });
});

document.getElementById("myReputationBtn").addEventListener("click", async () => {
  const req = getRequestContextFromForm();
  await callApi("My Reputation", "/api/reputation/me", {
    method: "GET",
    headers: validationHeaders(req.jwt, req.ip, req.fingerprint),
  });
});

document.getElementById("blockDemoForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const req = getRequestContextFromForm();
  const fd = new FormData(e.target);
  const attempts = Number(fd.get("attempts"));
  const delayMs = Number(fd.get("delay_ms"));

  log("Block Demo", `Starting up to ${attempts} bad requests (seconds = -1).`);

  for (let i = 1; i <= attempts; i += 1) {
    const { res, data } = await callApi(`Block Demo Attempt ${i}`, "/api/process", {
      method: "POST",
      headers: validationHeaders(req.jwt, req.ip, req.fingerprint),
      body: JSON.stringify({ seconds: -1 }),
    });

    if (res.status === 403 && data.error === "forbidden") {
      log("Block Demo", `User blocked on attempt ${i}.`);
      return;
    }

    if (res.status === 403 && data.error === "context_mismatch") {
      log("Block Demo", "Context mismatch happened. Use the same IP/fingerprint as login for block demo.");
      return;
    }

    await sleep(delayMs);
  }

  log("Block Demo", "Max attempts reached. If not blocked yet, run again.");
});

document.getElementById("summaryBtn").addEventListener("click", async () => {
  await callApi("Admin Summary", "/admin/reputation/summary", {
    method: "GET",
    headers: { ...adminKeyHeader() },
  });
});

document.getElementById("blockedBtn").addEventListener("click", async () => {
  await callApi("Blocked Users", "/admin/reputation/blocked-users", {
    method: "GET",
    headers: { ...adminKeyHeader() },
  });
});

document.getElementById("eventsBtn").addEventListener("click", async () => {
  await callApi("Recent Events", "/admin/reputation/events?limit=20", {
    method: "GET",
    headers: { ...adminKeyHeader() },
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
    headers: { ...adminKeyHeader() },
  });
});

updateSessionPreview();
