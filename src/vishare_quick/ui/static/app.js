(() => {
  "use strict";

  const tokenMeta = document.querySelector('meta[name="vishare-token"]');
  const versionMeta = document.querySelector('meta[name="vishare-version"]');
  const token = tokenMeta ? tokenMeta.content : "";
  const buildVersion = versionMeta ? versionMeta.content : "";
  const PAGE = document.body.dataset.page || "home";

  const ACTIVE_PHASES = new Set([
    "starting",
    "advertising",
    "connecting",
    "pin",
    "verifying",
    "consent",
    "receiving",
  ]);
  const ATTENTION_PHASES = new Set(["pin", "consent", "verifying"]);
  const FINAL_PHASES = new Set(["completed", "rejected", "failed", "cancelled"]);

  const state = {
    snapshot: null,
    online: null,
    busy: false,
    navigating: false,
    stopped: false,
    autoStartTried: false,
    pollTimer: 0,
    toastTimer: 0,
    activitySignature: "",
    announcement: "",
    resultAction: "receive",
    logsTrigger: null,
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  // ------------------------------------------------------------------- api
  async function request(path, body) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 10000);
    const init = {
      method: body === undefined ? "GET" : "POST",
      headers: {
        Accept: "application/json",
        "X-ViShare-Token": token,
      },
      cache: "no-store",
      signal: controller.signal,
    };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    try {
      const response = await fetch(path, init);
      let payload = null;
      try {
        payload = await response.json();
      } catch (_error) {
        payload = null;
      }
      if (!response.ok) {
        const message =
          payload && typeof payload.error === "string"
            ? payload.error
            : `The local receiver rejected that request (${response.status}).`;
        const error = new Error(message);
        error.payload = payload;
        throw error;
      }
      return payload;
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function postAction(path, body, options = {}) {
    if (state.busy) {
      return null;
    }
    state.busy = true;
    renderPage();
    try {
      const payload = await request(path, body === undefined ? {} : body);
      if (payload && payload.state) {
        applySnapshot(payload.state);
      }
      if (payload && payload.ok === false) {
        toast(
          options.failureMessage || "That action is not available right now.",
          "error"
        );
      } else if (options.successMessage) {
        toast(options.successMessage, "info");
      }
      return payload;
    } catch (error) {
      if (error.payload && error.payload.state) {
        applySnapshot(error.payload.state);
      }
      toast(options.failureMessage || error.message, "error");
      return null;
    } finally {
      state.busy = false;
      renderPage();
    }
  }

  // ------------------------------------------------------------------ poll
  async function poll() {
    window.clearTimeout(state.pollTimer);
    if (state.stopped) {
      return;
    }
    if (document.hidden) {
      schedulePoll(2500);
      return;
    }
    try {
      const snapshot = await request("/api/state");
      setOnline(true);
      applySnapshot(snapshot);
    } catch (_error) {
      setOnline(false);
      renderPage();
    } finally {
      schedulePoll();
    }
  }

  function schedulePoll(delay) {
    window.clearTimeout(state.pollTimer);
    if (state.stopped) {
      return;
    }
    const snapshot = state.snapshot;
    const live = snapshot && (ACTIVE_PHASES.has(snapshot.phase) || FINAL_PHASES.has(snapshot.phase));
    const next =
      typeof delay === "number" ? delay : live ? 500 : state.online === false ? 2200 : 1200;
    state.pollTimer = window.setTimeout(poll, next);
  }

  function setOnline(online) {
    if (state.online === online) {
      return;
    }
    const wasOffline = state.online === false;
    state.online = online;
    if (!online && !wasOffline && state.online !== null) {
      toast("The local receiver is not responding. Keep the app open.", "error");
    }
    renderPresence();
  }

  // --------------------------------------------------------------- snapshot
  function applySnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== "object") {
      return;
    }
    const previous = state.snapshot;
    state.snapshot = snapshot;
    state.online = true;

    renderPresence();
    routePhase();

    if (
      previous &&
      previous.phase !== snapshot.phase &&
      snapshot.phase === "advertising"
    ) {
      state.autoStartTried = true;
    }

    renderPage();
    renderActivity();
    announce(snapshot);
  }

  function routePhase() {
    const snapshot = state.snapshot;
    if (!snapshot || state.navigating) {
      return;
    }
    const phase = snapshot.phase;
    const attention = ATTENTION_PHASES.has(phase);
    const final = FINAL_PHASES.has(phase);

    if (PAGE === "home" || PAGE === "settings" || PAGE === "send") {
      if (attention) {
        autoNavigate("receive-request.html");
      }
      return;
    }

    if (PAGE === "receive") {
      if (final) {
        autoNavigate("receive-received.html");
      } else if (attention) {
        autoNavigate("receive-request.html");
      } else if (phase === "receiving") {
        autoNavigate("receive-receiving.html");
      } else if (phase === "idle") {
        ensureStarted();
      }
      return;
    }

    if (PAGE === "request") {
      if (phase === "receiving") {
        autoNavigate("receive-receiving.html");
      } else if (final) {
        autoNavigate("receive-received.html");
      } else if (phase === "idle" || phase === "advertising" || phase === "starting") {
        autoNavigate("receive-main.html");
      }
      return;
    }

    if (PAGE === "receiving") {
      if (final) {
        autoNavigate("receive-received.html");
      } else if (attention) {
        autoNavigate("receive-request.html");
      } else if (phase === "idle" || phase === "advertising" || phase === "starting") {
        autoNavigate("receive-main.html");
      }
      return;
    }

    if (PAGE === "received") {
      if (phase === "receiving") {
        autoNavigate("receive-receiving.html");
      } else if (attention) {
        autoNavigate("receive-request.html");
      } else if (
        phase === "idle" ||
        phase === "advertising" ||
        phase === "starting" ||
        phase === "connecting"
      ) {
        autoNavigate("index.html");
      }
    }
  }

  function autoNavigate(target) {
    if (state.navigating) {
      return;
    }
    const here = window.location.pathname.split("/").pop() || "index.html";
    if (here === target) {
      return;
    }
    state.navigating = true;
    window.location.replace(target);
  }

  function navigate(target) {
    state.stopped = true;
    window.clearTimeout(state.pollTimer);
    window.location.assign(target);
  }

  async function ensureStarted() {
    if (state.autoStartTried || state.busy) {
      return;
    }
    const snapshot = state.snapshot;
    if (!snapshot || snapshot.phase !== "idle") {
      return;
    }
    state.autoStartTried = true;
    state.busy = true;
    renderPage();
    try {
      const payload = await request("/api/start", {});
      if (payload && payload.state) {
        applySnapshot(payload.state);
      }
      if (payload && payload.ok === false) {
        toast("The receiver could not start. Check Settings.", "error");
      }
    } catch (_error) {
      toast("The receiver could not start. Check Settings.", "error");
    } finally {
      state.busy = false;
      renderPage();
    }
  }

  // --------------------------------------------------------------- render
  function renderPage() {
    renderPresence();
    if (PAGE === "home") {
      renderHome();
    } else if (PAGE === "receive") {
      renderReceive();
    } else if (PAGE === "request") {
      renderRequest();
    } else if (PAGE === "receiving") {
      renderReceiving();
    } else if (PAGE === "received") {
      renderReceived();
    } else if (PAGE === "settings") {
      renderSettings();
    }
    renderAvailability();
  }

  function renderPresence() {
    const snapshot = state.snapshot;
    const name = (snapshot && snapshot.device_name) || "ViShare Quick";
    let status;
    if (state.online === false) {
      status = "Interface disconnected";
    } else if (!snapshot) {
      status = "Connecting…";
    } else {
      status = presenceText(snapshot.phase);
    }
    for (const element of $$("[data-device-name]")) {
      setText(element, name);
    }
    for (const element of $$("[data-device-status]")) {
      setText(element, status);
    }
    for (const element of $$("[data-version]")) {
      setText(element, (snapshot && snapshot.version) || buildVersion || "alpha");
    }
    for (const element of $$("[data-download-dir]")) {
      setText(element, (snapshot && snapshot.download_dir) || "Downloads");
    }
    const receiveCard = $("#receiveCard");
    if (receiveCard) {
      receiveCard.classList.toggle(
        "is-live",
        Boolean(snapshot && ACTIVE_PHASES.has(snapshot.phase))
      );
    }
  }

  function presenceText(phase) {
    switch (phase) {
      case "starting":
        return "Starting receiver…";
      case "advertising":
        return "Visible to Everyone on this network";
      case "connecting":
        return "A device is connecting…";
      case "pin":
        return "Waiting for PIN confirmation";
      case "verifying":
        return "PIN confirmed";
      case "consent":
        return "Waiting for your approval";
      case "receiving":
        return "Receiving files…";
      case "completed":
        return "Last transfer complete";
      case "rejected":
        return "Last request declined";
      case "failed":
        return "Last transfer failed";
      case "cancelled":
        return "Last transfer cancelled";
      default:
        return "Receiver is off";
    }
  }

  function renderHome() {
    const snapshot = state.snapshot;
    const card = $("#receiveCard");
    if (card && snapshot && FINAL_PHASES.has(snapshot.phase)) {
      card.classList.remove("is-live");
    }
  }

  function renderReceive() {
    const snapshot = state.snapshot;
    const label = $("[data-receive-state]");
    if (!snapshot) {
      setText(label, state.online === false ? "Interface disconnected" : "Starting receiver…");
      return;
    }
    const phase = snapshot.phase;
    const text = {
      starting: "Starting receiver…",
      advertising: "Ready to receive",
      connecting: "A device is connecting…",
      pin: "Waiting for PIN confirmation…",
      verifying: "PIN confirmed",
      consent: "Waiting for your approval…",
      receiving: "Receiving files…",
      completed: "Last transfer complete",
      rejected: "Last request declined",
      failed: "The receiver needs attention",
      cancelled: "Last transfer cancelled",
    };
    setText(label, text[phase] || "Ready to receive");
  }

  function renderRequest() {
    const snapshot = state.snapshot;
    const senderName = $("[data-sender-name]");
    const requestText = $("[data-request-text]");
    const summary = $("[data-request-summary]");
    const pinWrap = $("[data-pin-wrap]");
    const pinText = $("[data-pin]");
    const note = $("[data-request-note]");
    const files = $("[data-request-files]");
    const buttons = $("[data-buttons]");
    const accept = $('[data-action="request-accept"]');
    const decline = $('[data-action="request-decline"]');

    if (!snapshot) {
      setText(senderName, "Waiting for a device…");
      setText(requestText, "Connecting to the local receiver…");
      setText(summary, "Please wait.");
      if (pinWrap) pinWrap.hidden = true;
      if (note) note.hidden = true;
      if (files) files.hidden = true;
      if (buttons) buttons.hidden = true;
      return;
    }

    const phase = snapshot.phase;
    if (phase === "pin") {
      const pin = snapshot.pin;
      const seconds = pin ? Math.max(0, Number(pin.seconds_remaining) || 0) : 0;
      setText(senderName, "A device wants to connect");
      setText(requestText, "Compare the 4-digit code");
      setText(summary, "Check that the other device shows this code.");
      if (pinWrap) pinWrap.hidden = !pin;
      if (pinText) setText(pinText, pin ? `PIN: ${pin.code}` : "PIN: ----");
      if (note) {
        note.hidden = false;
        if (!pin) {
          setText(note, "Waiting for the code…");
        } else if (seconds > 0) {
          const minutes = Math.floor(seconds / 60);
          const rest = String(seconds % 60).padStart(2, "0");
          setText(note, `Code expires in ${minutes}:${rest}`);
        } else {
          setText(note, "This code expired. Decline to fail closed.");
        }
      }
      if (files) {
        files.hidden = true;
        files.replaceChildren();
      }
      if (buttons) buttons.hidden = false;
      if (accept) {
        setText(accept, "Codes match");
        accept.disabled = state.busy || !pin || seconds <= 0;
      }
      if (decline) {
        setText(decline, "Codes don't match");
        decline.disabled = state.busy || !pin;
      }
      return;
    }

    if (phase === "consent") {
      const request = snapshot.request;
      const offered = request ? request.files || [] : [];
      const total = request ? request.total_size : 0;
      setText(senderName, "Incoming files");
      setText(requestText, "Accept request?");
      setText(
        summary,
        offered.length
          ? `${offered.length} ${offered.length === 1 ? "file" : "files"} · ${formatBytes(total)}`
          : "Preparing the file list…"
      );
      if (pinWrap) pinWrap.hidden = true;
      if (pinText) setText(pinText, "");
      if (note) {
        note.hidden = true;
        setText(note, "");
      }
      if (files) {
        files.hidden = false;
        renderOfferedFiles(files, offered);
      }
      if (buttons) buttons.hidden = false;
      if (accept) {
        setText(accept, "Accept");
        accept.disabled = state.busy || offered.length === 0;
      }
      if (decline) {
        setText(decline, "Decline");
        decline.disabled = state.busy || offered.length === 0;
      }
      return;
    }

    if (phase === "verifying") {
      setText(senderName, "Code confirmed");
      setText(requestText, "Waiting for the file list…");
      setText(summary, "The other device is preparing the files.");
      if (pinWrap) pinWrap.hidden = true;
      if (note) note.hidden = true;
      if (files) {
        files.hidden = true;
        files.replaceChildren();
      }
      if (buttons) buttons.hidden = true;
      return;
    }

    if (phase === "connecting") {
      setText(senderName, "A device is connecting");
      setText(requestText, "Completing the secure handshake…");
      setText(summary, "Please wait for the request to arrive.");
      if (pinWrap) pinWrap.hidden = true;
      if (note) note.hidden = true;
      if (files) files.hidden = true;
      if (buttons) buttons.hidden = true;
      return;
    }

    setText(senderName, "Waiting for a request…");
    setText(requestText, "Nothing needs your attention.");
    setText(summary, "Keep this window open.");
    if (pinWrap) pinWrap.hidden = true;
    if (note) note.hidden = true;
    if (files) files.hidden = true;
    if (buttons) buttons.hidden = true;
  }

  function renderReceiving() {
    const snapshot = state.snapshot;
    const progress = snapshot && snapshot.progress;
    const percent = progress ? clampPercent(progress.percent) : 0;
    const ring = $("[data-progress-ring]");
    if (ring) {
      ring.style.setProperty("--p", String(percent));
      ring.setAttribute("aria-valuenow", String(percent));
    }
    setText(
      $("[data-progress-text]"),
      progress ? `Receiving... ${percent}%` : "Receiving..."
    );
    setText(
      $("[data-progress-summary]"),
      progress
        ? `${progress.files.length} ${
            progress.files.length === 1 ? "file" : "files"
          } · ${formatBytes(progress.received_bytes)} of ${formatBytes(
            progress.total_bytes
          )}`
        : "Preparing the transfer…"
    );
    const list = $("[data-progress-files]");
    if (list) {
      renderProgressFiles(list, progress ? progress.files : []);
    }
  }

  function renderReceived() {
    const snapshot = state.snapshot;
    if (!snapshot) {
      return;
    }
    const phase = snapshot.phase;
    const completed = phase === "completed";
    const result = snapshot.result || {};
    const files = completed ? result.files || [] : [];
    const ring = $("[data-result-ring]");
    const tick = $("[data-result-tick]");
    const symbol = $("[data-result-symbol]");
    const summary = $("[data-result-summary]");
    const list = $("[data-result-files]");
    const primary = $("[data-primary-label]");

    const titles = {
      completed: ["Received", "Transfer complete"],
      rejected: ["Request declined", "Nothing was saved"],
      failed: ["Transfer failed", "Transfer stopped"],
      cancelled: ["Transfer cancelled", "Partial files removed"],
    };
    const chosen = titles[phase] || ["Transfer stopped", "No files were saved"];
    setText($("[data-result-title]"), chosen[0]);
    setText($("[data-result-text]"), chosen[1]);
    setText(
      $("[data-result-message]"),
      snapshot.error ||
        (completed
          ? "The files are saved in your download folder."
          : "No files were saved.")
    );

    if (completed) {
      const total = result.total_size || 0;
      setText(
        summary,
        files.length
          ? `${files.length} ${files.length === 1 ? "file" : "files"} · ${formatBytes(
              total
            )}`
          : "The transfer completed."
      );
      if (ring) ring.classList.remove("is-attention");
      if (tick) tick.hidden = false;
      if (symbol) symbol.hidden = true;
      if (list) {
        list.hidden = files.length === 0;
        renderResultFiles(list, files);
      }
      setText(primary, "Open in Files");
      state.resultAction = "open-downloads";
    } else {
      setText(summary, "No files were saved.");
      if (ring) ring.classList.add("is-attention");
      if (tick) tick.hidden = true;
      if (symbol) {
        symbol.hidden = false;
        setText(symbol, "!");
      }
      if (list) {
        list.hidden = true;
        list.replaceChildren();
      }
      if (phase === "failed") {
        setText(primary, "Try again");
        state.resultAction = "retry";
      } else {
        setText(primary, "Back to receiving");
        state.resultAction = "receive";
      }
    }
  }

  function renderSettings() {
    const snapshot = state.snapshot;
    const active = Boolean(snapshot && ACTIVE_PHASES.has(snapshot.phase));
    const input = $("[data-name-input]");
    const save = $("[data-name-save]");
    const hint = $("[data-name-hint]");
    if (input && document.activeElement !== input) {
      input.value = (snapshot && snapshot.device_name) || "ViShare Quick";
    }
    if (input) {
      input.disabled = state.busy || active;
    }
    if (save) {
      save.disabled = state.busy || active;
    }
    if (hint) {
      setText(
        hint,
        active
          ? "Stop receiving before changing the device name."
          : "Up to 64 characters. Nearby devices see this name."
      );
    }
  }

  function renderAvailability() {
    const snapshot = state.snapshot;
    const stopButtons = $$("[data-stop-receive]");
    const active = Boolean(snapshot && ACTIVE_PHASES.has(snapshot.phase));
    for (const button of stopButtons) {
      button.disabled = state.busy || !snapshot || snapshot.phase === "idle";
    }
    if (PAGE === "request") {
      const accept = $('[data-action="request-accept"]');
      const decline = $('[data-action="request-decline"]');
      if (accept) accept.disabled = accept.disabled || state.busy;
      if (decline) decline.disabled = decline.disabled || state.busy;
    }
    if (PAGE === "receiving") {
      const cancel = $('[data-action="cancel-transfer"]');
      if (cancel) cancel.disabled = state.busy || !active;
    }
    if (PAGE === "settings") {
      const input = $("[data-name-input]");
      const save = $("[data-name-save]");
      if (input && state.busy) input.disabled = true;
      if (save && state.busy) save.disabled = true;
    }
  }

  function announce(snapshot) {
    const message = phaseAnnouncement(snapshot);
    if (!message || message === state.announcement) {
      return;
    }
    state.announcement = message;
    setText($("#status"), message);
  }

  function phaseAnnouncement(snapshot) {
    switch (snapshot.phase) {
      case "idle":
        return "Receiver is off.";
      case "starting":
        return "Starting the receiver.";
      case "advertising":
        return "Ready to receive.";
      case "connecting":
        return "A device connected. Completing the secure handshake.";
      case "pin":
        return snapshot.pin
          ? `PIN verification. The local code is ${String(snapshot.pin.code)
              .split("")
              .join(" ")}.`
          : "PIN verification.";
      case "verifying":
        return "PIN confirmed. Waiting for the file list.";
      case "consent":
        return `Incoming request for ${
          snapshot.request ? snapshot.request.files.length : 0
        } files.`;
      case "receiving":
        return "Receiving files.";
      case "completed":
        return "Files received.";
      case "rejected":
        return "The request was declined.";
      case "failed":
        return "The transfer failed.";
      case "cancelled":
        return "The transfer was cancelled.";
      default:
        return "";
    }
  }

  // ---------------------------------------------------------------- files
  function renderOfferedFiles(container, files) {
    const fragment = document.createDocumentFragment();
    for (const file of files) {
      const kind = String(file.kind || "").replaceAll("_", " ").toLowerCase();
      const meta = [formatBytes(file.size)];
      if (kind && kind !== "unknown") {
        meta.push(kind);
      } else if (file.mime) {
        meta.push(String(file.mime));
      }
      fragment.append(createTransferRow(file.name, meta.join(" · ")));
    }
    container.replaceChildren(fragment);
  }

  function renderProgressFiles(container, files) {
    const fragment = document.createDocumentFragment();
    for (const file of files) {
      const total = Math.max(0, Number(file.size) || 0);
      const received = Math.max(0, Number(file.received) || 0);
      const percent = file.done
        ? 100
        : total > 0
          ? clampPercent(Math.floor((received * 100) / total))
          : 0;
      const row = createTransferRow(
        file.name,
        `${formatBytes(received)} of ${formatBytes(total)}`,
        percent,
        file.done
      );
      fragment.append(row);
    }
    container.replaceChildren(fragment);
  }

  function renderResultFiles(container, files) {
    const fragment = document.createDocumentFragment();
    for (const file of files) {
      const display = file.saved_name || file.name || "File";
      const meta = [formatBytes(file.size)];
      if (file.name && file.saved_name && file.name !== file.saved_name) {
        meta.push(`sent as ${file.name}`);
      }
      fragment.append(createTransferRow(display, meta.join(" · ")));
    }
    container.replaceChildren(fragment);
  }

  function createTransferRow(name, metaText, percent, done) {
    const row = document.createElement("li");
    row.className = "transfer-row";

    const main = document.createElement("div");
    main.className = "transfer-main";

    const title = document.createElement("span");
    title.className = "transfer-name";
    setText(title, name || "File");
    title.title = name || "File";

    const meta = document.createElement("span");
    meta.className = "transfer-meta";
    setText(meta, metaText);

    main.append(title, meta);

    if (typeof percent === "number") {
      const track = document.createElement("span");
      track.className = "transfer-track";
      const fill = document.createElement("span");
      fill.className = "transfer-fill";
      fill.style.width = `${percent}%`;
      track.append(fill);
      main.append(track);
    }

    const status = document.createElement("span");
    status.className = "transfer-status";
    if (done) {
      const tick = document.createElement("img");
      tick.src = "/assets/tick.png";
      tick.alt = "Received";
      status.append(tick);
    } else if (typeof percent === "number") {
      setText(status, `${percent}%`);
    }

    row.append(main, status);
    return row;
  }

  // -------------------------------------------------------------- activity
  function renderActivity() {
    const events = (state.snapshot && state.snapshot.events) || [];
    const signature = events.map((event) => `${event.time}${event.text}`).join("|");
    if (signature === state.activitySignature) {
      return;
    }
    state.activitySignature = signature;
    const list = $("[data-activity-list]");
    const empty = $("[data-activity-empty]");
    if (!list) {
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const event of events.slice().reverse()) {
      const item = document.createElement("li");
      item.className = "activity-item";
      const time = document.createElement("span");
      time.className = "activity-time";
      setText(time, event.time || "");
      const text = document.createElement("span");
      text.className = "activity-text";
      setText(text, event.text || "");
      item.append(time, text);
      fragment.append(item);
    }
    list.replaceChildren(fragment);
    if (empty) {
      empty.hidden = events.length > 0;
    }
  }

  function openLogs() {
    const panel = $("[data-logs]");
    if (!panel) {
      return;
    }
    state.logsTrigger = document.activeElement;
    panel.hidden = false;
    const scrim = $("[data-logs-scrim]");
    if (scrim) {
      scrim.hidden = false;
    }
    const close = $(".activity-close");
    if (close) {
      close.focus();
    }
  }

  function closeLogs() {
    const panel = $("[data-logs]");
    if (!panel || panel.hidden) {
      return;
    }
    panel.hidden = true;
    const scrim = $("[data-logs-scrim]");
    if (scrim) {
      scrim.hidden = true;
    }
    if (state.logsTrigger && typeof state.logsTrigger.focus === "function") {
      state.logsTrigger.focus();
    }
  }

  // --------------------------------------------------------------- actions
  async function openReceive() {
    const snapshot = state.snapshot;
    if (snapshot && FINAL_PHASES.has(snapshot.phase)) {
      const payload = await postAction("/api/dismiss", {}, {
        failureMessage: "The receiver could not be reset.",
      });
      if (!payload) {
        return;
      }
    }
    navigate("receive-main.html");
  }

  async function stopReceiver() {
    const snapshot = state.snapshot;
    if (snapshot && snapshot.phase !== "idle") {
      if (!window.confirm("Stop receiving? Any pending request is declined.")) {
        return;
      }
      const payload = await postAction("/api/stop", {}, {
        failureMessage: "The receiver could not be stopped cleanly.",
      });
      if (!payload) {
        return;
      }
    }
    if (PAGE === "receive") {
      navigate("index.html");
    }
  }

  async function requestDecision(accept) {
    const snapshot = state.snapshot;
    if (!snapshot) {
      return;
    }
    if (snapshot.phase === "pin") {
      const pin = snapshot.pin;
      const seconds = pin ? Math.max(0, Number(pin.seconds_remaining) || 0) : 0;
      if (accept && (!pin || seconds <= 0)) {
        toast("The code expired. Decline to fail closed.", "error");
        return;
      }
      await postAction(
        "/api/pin",
        { match: accept },
        {
          failureMessage: "The PIN decision could not be recorded.",
        }
      );
      return;
    }
    if (snapshot.phase === "consent") {
      await postAction(
        "/api/consent",
        { accept },
        {
          successMessage: accept ? "Accepting files…" : "Declining the request…",
          failureMessage: "The consent decision could not be recorded.",
        }
      );
    }
  }

  async function leaveRequest() {
    const snapshot = state.snapshot;
    if (snapshot && snapshot.phase === "pin") {
      await postAction("/api/pin", { match: false }, {
        failureMessage: "The request could not be declined.",
      });
    } else if (snapshot && snapshot.phase === "consent") {
      await postAction("/api/consent", { accept: false }, {
        failureMessage: "The request could not be declined.",
      });
    }
    navigate("index.html");
  }

  async function cancelTransfer() {
    if (
      !window.confirm(
        "Cancel this transfer? Partial files will be removed and nothing will be saved."
      )
    ) {
      return;
    }
    await postAction("/api/cancel", {}, {
      successMessage: "Cancelling the transfer and removing partial files.",
      failureMessage: "The transfer could not be cancelled.",
    });
  }

  async function openDownloads() {
    await postAction("/api/open-downloads", {}, {
      failureMessage: "The download folder could not be opened.",
    });
  }

  async function handleResultPrimary() {
    if (state.resultAction === "open-downloads") {
      await openDownloads();
      return;
    }
    const payload = await postAction("/api/dismiss", {}, {
      failureMessage: "The receiver could not be reset.",
    });
    if (!payload) {
      return;
    }
    navigate("receive-main.html");
  }

  async function finishResult() {
    await postAction("/api/dismiss", {}, {
      failureMessage: "The receiver could not be reset.",
    });
    navigate("index.html");
  }

  async function saveDeviceName(event) {
    event.preventDefault();
    const input = $("[data-name-input]");
    if (!input) {
      return;
    }
    const name = input.value.trim();
    if (!name) {
      toast("Enter a device name first.", "error");
      input.focus();
      return;
    }
    const payload = await postAction(
      "/api/device-name",
      { name },
      { successMessage: "Device name updated." }
    );
    if (payload && payload.ok === false) {
      toast("Stop receiving before changing the device name.", "error");
    }
  }

  async function shutdown() {
    if (
      !window.confirm(
        "Stop receiving and close the local ViShare Quick interface?"
      )
    ) {
      return;
    }
    state.busy = true;
    state.stopped = true;
    window.clearTimeout(state.pollTimer);
    renderPage();
    try {
      await request("/api/shutdown", {});
    } catch (_error) {
      // The server may close the connection before the response is read.
    }
    setOnline(false);
    toast("ViShare Quick has stopped. You can close this tab.");
  }

  function toast(message, kind) {
    let element = $(".toast");
    if (!element) {
      element = document.createElement("div");
      element.className = "toast";
      element.setAttribute("role", "status");
      document.body.append(element);
    }
    window.clearTimeout(state.toastTimer);
    element.textContent = message;
    element.classList.toggle("is-error", kind === "error");
    element.hidden = false;
    state.toastTimer = window.setTimeout(() => {
      element.hidden = true;
    }, 4200);
  }

  // --------------------------------------------------------------- helpers
  function clampPercent(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) {
      return 0;
    }
    return Math.max(0, Math.min(100, Math.round(number)));
  }

  function formatBytes(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) {
      return "—";
    }
    if (bytes < 1024) {
      return `${Math.round(bytes)} B`;
    }
    const units = ["KB", "MB", "GB", "TB"];
    let amount = bytes / 1024;
    let index = 0;
    while (amount >= 1024 && index < units.length - 1) {
      amount /= 1024;
      index += 1;
    }
    const digits = amount >= 10 ? 1 : 2;
    return `${amount.toFixed(digits)} ${units[index]}`;
  }

  function setText(element, value) {
    if (!element) {
      return;
    }
    const text = String(value == null ? "" : value);
    if (element.textContent !== text) {
      element.textContent = text;
    }
  }

  // ----------------------------------------------------------------- wiring
  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-href], [data-action]");
    if (!target) {
      return;
    }
    if (target.hasAttribute("data-href")) {
      event.preventDefault();
      navigate(target.getAttribute("data-href"));
      return;
    }
    const action = target.getAttribute("data-action");
    switch (action) {
      case "open-receive":
        openReceive();
        break;
      case "open-logs":
        openLogs();
        break;
      case "close-logs":
        closeLogs();
        break;
      case "stop-receive":
        stopReceiver();
        break;
      case "request-accept":
        requestDecision(true);
        break;
      case "request-decline":
        requestDecision(false);
        break;
      case "leave-request":
        leaveRequest();
        break;
      case "cancel-transfer":
        cancelTransfer();
        break;
      case "open-downloads":
        openDownloads();
        break;
      case "result-primary":
        handleResultPrimary();
        break;
      case "finish":
        finishResult();
        break;
      case "shutdown":
        shutdown();
        break;
      default:
        break;
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeLogs();
      return;
    }
    if (event.key !== "Enter" && event.key !== " ") {
      return;
    }
    const button = event.target.closest('[role="button"]');
    if (button) {
      event.preventDefault();
      button.click();
    }
  });

  const nameForm = $("#nameForm");
  if (nameForm) {
    nameForm.addEventListener("submit", saveDeviceName);
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      poll();
    }
  });

  // The inline SVG uses SMIL animations; CSS cannot pause those.
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    for (const svg of document.querySelectorAll("svg")) {
      if (typeof svg.pauseAnimations === "function") {
        svg.pauseAnimations();
      }
    }
  }

  renderPresence();
  renderPage();
  poll();
})();
