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
  const SEND_ACTIVE_PHASES = new Set([
    "connecting",
    "handshake",
    "offering",
    "pin",
    "waiting",
    "sending",
    "finishing",
  ]);
  const SEND_FINAL_PHASES = new Set(["completed", "failed", "cancelled"]);

  const state = {
    snapshot: null,
    online: null,
    busy: false,
    navigating: false,
    stopped: false,
    autoStartTried: false,
    sendDiscoverTried: false,
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
    const send = snapshot && snapshot.send;
    const live =
      snapshot &&
      (ACTIVE_PHASES.has(snapshot.phase) ||
        FINAL_PHASES.has(snapshot.phase) ||
        (send && SEND_ACTIVE_PHASES.has(send.phase)));
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
    routeSendPhase();

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

    if (PAGE === "sending" || PAGE === "send-failed") {
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

  function routeSendPhase() {
    const snapshot = state.snapshot;
    const send = snapshot && snapshot.send;
    if (!send) {
      return;
    }
    if (PAGE === "send") {
      if (SEND_ACTIVE_PHASES.has(send.phase)) {
        autoNavigate("send-sending.html");
      } else if (
        !state.busy &&
        !state.sendDiscoverTried &&
        !send.discovering &&
        (send.peers || []).length === 0
      ) {
        state.sendDiscoverTried = true;
        postAction("/api/send/discover", {}, {
          failureMessage: "Nearby devices could not be listed.",
        });
      }
      return;
    }
    if (PAGE === "sending") {
      if (send.phase === "failed" || send.phase === "cancelled") {
        autoNavigate("send-failed.html");
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
    } else if (PAGE === "send") {
      renderSend();
    } else if (PAGE === "sending") {
      renderSending();
    } else if (PAGE === "send-failed") {
      renderSendFailed();
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

  function sendSnapshot() {
    return state.snapshot && state.snapshot.send ? state.snapshot.send : null;
  }

  function sendStatusText(send) {
    if (!send) {
      return "Connecting…";
    }
    if (send.phase === "pin") {
      return "Waiting for PIN confirmation";
    }
    if (SEND_ACTIVE_PHASES.has(send.phase)) {
      return "Sending files";
    }
    if (send.phase === "completed") {
      return "Last send complete";
    }
    if (send.phase === "failed") {
      return "Last send failed";
    }
    if (send.phase === "cancelled") {
      return "Last send cancelled";
    }
    if (send.discovering) {
      return "Looking for nearby devices";
    }
    return "Ready to send on this network";
  }

  function renderSendStatus() {
    const send = sendSnapshot();
    for (const element of $$("[data-send-status]")) {
      setText(element, sendStatusText(send));
    }
  }

  function renderSendFiles(container, files, progress) {
    if (!container) {
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const file of files) {
      const total = Math.max(0, Number(file.size) || 0);
      if (progress) {
        const sent = Math.max(0, Number(file.sent) || 0);
        const percent = file.done
          ? 100
          : total > 0
            ? clampPercent(Math.floor((sent * 100) / total))
            : 0;
        fragment.append(
          createTransferRow(
            file.name,
            `${formatBytes(sent)} of ${formatBytes(total)}`,
            percent,
            file.done
          )
        );
      } else {
        fragment.append(createTransferRow(file.name, formatBytes(total)));
      }
    }
    container.replaceChildren(fragment);
  }

  function renderSendPeerList(container, send) {
    if (!container) {
      return;
    }
    const fragment = document.createDocumentFragment();
    const disabled = state.busy || (send.files || []).length === 0;
    for (const peer of send.peers || []) {
      const item = document.createElement("li");
      item.className = "send-peer";
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.action = "send-to-peer";
      button.dataset.peerKey = peer.key;
      button.disabled = disabled;

      const icon = document.createElement("span");
      icon.className = "send-peer-icon";
      const image = document.createElement("img");
      image.src = "/assets/laptop.png";
      image.alt = "";
      icon.append(image);

      const main = document.createElement("span");
      main.className = "send-peer-main";
      const name = document.createElement("span");
      name.className = "send-peer-name mainText";
      setText(name, peer.name || "Nearby device");
      const meta = document.createElement("span");
      meta.className = "send-peer-meta mainText";
      setText(
        meta,
        `${peer.device_type_label || "Device"} · ${peer.host}:${peer.port}`
      );
      main.append(name, meta);

      const action = document.createElement("span");
      action.className = "send-peer-action";
      setText(action, "Send");

      button.append(icon, main, action);
      item.append(button);
      fragment.append(item);
    }
    container.replaceChildren(fragment);
  }

  function renderSend() {
    renderSendStatus();
    const send = sendSnapshot();
    const fileStatus = $("[data-send-files-status]");
    const fileList = $("[data-send-file-list]");
    const devices = $("[data-send-devices]");
    const deviceText = $("[data-send-device-text]");
    const peerList = $("[data-send-peer-list]");
    const windowsShare = $("[data-windows-share]");
    const windowsStatus = $("[data-windows-share-status]");
    const windowsButton = $('[data-action="windows-share"]');
    const error = $("[data-send-error]");
    if (!send) {
      setText(fileStatus, "Connecting…");
      return;
    }
    const files = send.files || [];
    setText(
      fileStatus,
      files.length
        ? `${files.length} ${files.length === 1 ? "file" : "files"} · ${formatBytes(
            send.total_size
          )}`
        : "None selected"
    );
    if (fileList) {
      fileList.hidden = files.length === 0;
      renderSendFiles(fileList, files, false);
    }
    const peers = send.peers || [];
    if (devices) {
      devices.hidden = peers.length > 0;
    }
    if (deviceText) {
      if (send.discovering) {
        setText(deviceText, "Looking for nearby devices...");
      } else if (peers.length === 0) {
        setText(
          deviceText,
          "No nearby devices found. Open Quick Share on the device and refresh."
        );
      }
    }
    if (peerList) {
      peerList.hidden = peers.length === 0;
      renderSendPeerList(peerList, send);
    }
    if (error) {
      error.hidden = !send.error;
      setText(error, send.error || "");
    }
    const refresh = $('[data-action="refresh-peers"]');
    if (refresh) {
      refresh.disabled = state.busy || send.discovering;
    }
    const clear = $('[data-action="clear-files"]');
    if (clear) {
      clear.disabled = state.busy || files.length === 0;
    }
    const nearby = send.nearby_share || {};
    if (windowsShare) {
      windowsShare.hidden = !nearby.supported;
    }
    if (nearby.supported) {
      setText(windowsStatus, nearby.reason || "");
      if (windowsButton) {
        windowsButton.disabled =
          state.busy ||
          !nearby.available ||
          files.length === 0 ||
          SEND_ACTIVE_PHASES.has(send.phase);
        windowsButton.title = nearby.available
          ? "Open the Windows share sheet"
          : nearby.reason || "Windows sharing is unavailable.";
      }
    }
  }

  function sendStateForPhase(phase) {
    if (phase === "pin") {
      return "waiting";
    }
    if (phase === "sending" || phase === "finishing") {
      return "sending";
    }
    if (phase === "completed") {
      return "sent";
    }
    if (phase === "failed" || phase === "cancelled") {
      return "failed";
    }
    if (phase === "waiting") {
      return "waiting";
    }
    return "found";
  }

  function sendPhaseLabel(phase) {
    const labels = {
      connecting: "Connecting...",
      handshake: "Negotiating encryption...",
      offering: "Offering the files...",
      pin: "Waiting...",
      waiting: "Waiting for the device to accept...",
      sending: "Sending...",
      finishing: "Finishing...",
      completed: "Sent",
      failed: "Failed",
      cancelled: "Cancelled",
    };
    return labels[phase] || "Ready";
  }

  function renderSending() {
    renderSendStatus();
    const send = sendSnapshot();
    if (!send) {
      return;
    }
    const files = send.files || [];
    const fileStatus = $("[data-send-files-status]");
    const fileList = $("[data-send-file-list]");
    const progressList = $("[data-send-progress]");
    const peerName = $("[data-send-peer-name]");
    const deviceState = $("[data-send-device-state]");
    const pinText = $("[data-send-pin]");
    const error = $("[data-send-error]");
    const pinActions = $("[data-send-pin-actions]");
    const cancelAction = $("[data-send-cancel]");
    const resultActions = $("[data-send-result-actions]");
    const peer = send.peer || (send.result ? { name: send.result.peer_name } : null);
    const phase = send.phase;
    const dataState = sendStateForPhase(phase);
    document.body.dataset.state = dataState;

    setText(
      fileStatus,
      files.length
        ? `${files.length} ${files.length === 1 ? "file" : "files"} · ${formatBytes(
            send.total_size
          )}`
        : "None selected"
    );
    if (fileList) {
      fileList.hidden = files.length === 0;
      renderSendFiles(fileList, files, false);
    }
    setText(peerName, (peer && (peer.name || peer.device_name)) || "Nearby device");
    setText(deviceState, sendPhaseLabel(phase));

    const showPin = phase === "pin" && send.pin;
    if (pinText) {
      pinText.hidden = !showPin;
      setText(pinText, showPin ? `PIN: ${send.pin.code}` : "");
    }

    if (progressList) {
      const progress = send.progress;
      const visible =
        Boolean(progress) &&
        (phase === "sending" || phase === "finishing" || phase === "completed");
      progressList.hidden = !visible;
      if (visible) {
        renderSendFiles(progressList, progress.files || [], true);
      }
      const arc = $(".ring-arc");
      if (arc) {
        if (phase === "sending" || phase === "finishing") {
          const percent = progress ? clampPercent(progress.percent) : 0;
          arc.style.strokeDashoffset = String(182.2 * (1 - percent / 100));
        } else {
          arc.style.strokeDashoffset = "";
        }
      }
    }

    if (error) {
      const showError =
        (phase === "failed" || phase === "cancelled") && Boolean(send.error);
      error.hidden = !showError;
      setText(error, showError ? send.error : "");
    }
    if (pinActions) {
      pinActions.hidden = !showPin;
    }
    if (cancelAction) {
      cancelAction.hidden = !SEND_ACTIVE_PHASES.has(phase);
    }
    if (resultActions) {
      resultActions.hidden = phase !== "completed";
    }
  }

  function renderSendFailed() {
    renderSendStatus();
    const send = sendSnapshot();
    const fileStatus = $("[data-send-files-status]");
    const fileList = $("[data-send-file-list]");
    const peerName = $("[data-send-peer-name]");
    const deviceState = $("[data-send-device-state]");
    const error = $("[data-send-error]");
    if (!send) {
      return;
    }
    const files = send.files || [];
    const peer = send.peer || (send.result ? { name: send.result.peer_name } : null);
    document.body.dataset.state = "failed";
    setText(
      fileStatus,
      files.length
        ? `${files.length} ${files.length === 1 ? "file" : "files"} · ${formatBytes(
            send.total_size
          )}`
        : "None selected"
    );
    if (fileList) {
      fileList.hidden = files.length === 0;
      renderSendFiles(fileList, files, false);
    }
    setText(peerName, (peer && (peer.name || peer.device_name)) || "Nearby device");
    setText(deviceState, send.phase === "cancelled" ? "Cancelled" : "Failed");
    setText(
      error,
      send.error || "The send stopped before it finished."
    );
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

  // ------------------------------------------------------------------ send
  async function openSend() {
    const send = sendSnapshot();
    if (send && SEND_ACTIVE_PHASES.has(send.phase)) {
      navigate("send-sending.html");
      return;
    }
    if (send && SEND_FINAL_PHASES.has(send.phase)) {
      await postAction("/api/send/dismiss", {}, {
        failureMessage: "The last send could not be dismissed.",
      });
    }
    state.sendDiscoverTried = false;
    navigate("send-send.html");
  }

  function browseSendFiles() {
    const input = $("[data-file-input]");
    if (input) {
      input.click();
    }
  }

  async function uploadSendFiles(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) {
      return;
    }
    state.busy = true;
    renderPage();
    try {
      for (const file of files) {
        if (!file.size) {
          toast(`"${file.name}" is empty and cannot be sent.`, "error");
          continue;
        }
        const response = await fetch("/api/send/add-file", {
          method: "POST",
          headers: {
            Accept: "application/json",
            "X-ViShare-Token": token,
            "X-ViShare-Filename": encodeURIComponent(file.name),
            "Content-Type": "application/octet-stream",
          },
          body: file,
        });
        let payload = null;
        try {
          payload = await response.json();
        } catch (_error) {
          payload = null;
        }
        if (payload && payload.state) {
          applySnapshot(payload.state);
        }
        if (!response.ok || (payload && payload.ok === false)) {
          toast(
            (payload && payload.error) ||
              `"${file.name}" could not be added to the selection.`,
            "error"
          );
        }
      }
    } catch (_error) {
      toast("The selected files could not be added.", "error");
    } finally {
      state.busy = false;
      renderPage();
    }
  }

  async function clearSendFiles() {
    const send = sendSnapshot();
    if (!send || (send.files || []).length === 0) {
      return;
    }
    await postAction("/api/send/clear-files", {}, {
      successMessage: "The selection was cleared.",
      failureMessage: "The selection could not be cleared.",
    });
  }

  async function refreshSendPeers() {
    state.sendDiscoverTried = true;
    await postAction("/api/send/discover", {}, {
      successMessage: "Looking for nearby devices…",
      failureMessage: "Nearby devices could not be listed.",
    });
  }

  async function shareViaWindows() {
    const send = sendSnapshot();
    if (!send || (send.files || []).length === 0) {
      toast("Select at least one file first.", "error");
      return;
    }
    await postAction("/api/send/windows-share", {}, {
      successMessage: "Choose a nearby device in the Windows share window.",
      failureMessage: "The Windows share sheet could not be opened.",
    });
  }

  async function sendToPeer(peerKey) {
    const send = sendSnapshot();
    if (!send || (send.files || []).length === 0) {
      toast("Select at least one file first.", "error");
      return;
    }
    const payload = await postAction(
      "/api/send/start",
      { peer: peerKey },
      {
        failureMessage: "The send could not be started.",
      }
    );
    if (payload && payload.ok !== false) {
      navigate("send-sending.html");
    }
  }

  async function sendPinDecision(match) {
    if (!match) {
      await postAction("/api/send/pin", { match: false }, {
        successMessage: "The send was declined.",
        failureMessage: "The decision could not be recorded.",
      });
      return;
    }
    await postAction("/api/send/pin", { match: true }, {
      successMessage: "Codes confirmed.",
      failureMessage: "The decision could not be recorded.",
    });
  }

  async function cancelSend() {
    if (
      !window.confirm(
        "Cancel this send? The transfer will stop and nothing else will be sent."
      )
    ) {
      return;
    }
    await postAction("/api/send/cancel", {}, {
      successMessage: "Cancelling the send…",
      failureMessage: "The send could not be cancelled.",
    });
  }

  async function leaveSend() {
    const send = sendSnapshot();
    let proceed = true;
    if (send && SEND_ACTIVE_PHASES.has(send.phase)) {
      if (!window.confirm("Leave and cancel this send?")) {
        return;
      }
      const payload = await postAction("/api/send/cancel", {}, {
        failureMessage: "The send could not be cancelled.",
      });
      proceed = Boolean(payload && payload.ok !== false);
    } else if (send && SEND_FINAL_PHASES.has(send.phase)) {
      await postAction("/api/send/dismiss", {}, {
        failureMessage: "The last send could not be dismissed.",
      });
    }
    if (proceed) {
      navigate("index.html");
    }
  }

  async function sendAnother() {
    await postAction("/api/send/dismiss", {}, {
      failureMessage: "The last send could not be dismissed.",
    });
    state.sendDiscoverTried = true;
    navigate("send-send.html");
  }

  async function retrySend() {
    await postAction("/api/send/dismiss", {}, {
      failureMessage: "The last send could not be dismissed.",
    });
    state.sendDiscoverTried = false;
    navigate("send-send.html");
  }

  async function finishSend() {
    const send = sendSnapshot();
    if (send && SEND_FINAL_PHASES.has(send.phase)) {
      await postAction("/api/send/dismiss", {}, {
        failureMessage: "The last send could not be dismissed.",
      });
    }
    navigate("index.html");
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
    toast("ViShare Quick has stopped. You can close this window.");
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
      case "open-send":
        openSend();
        break;
      case "browse-files":
        browseSendFiles();
        break;
      case "refresh-peers":
        refreshSendPeers();
        break;
      case "windows-share":
        shareViaWindows();
        break;
      case "clear-files":
        clearSendFiles();
        break;
      case "send-to-peer":
        sendToPeer(target.dataset.peerKey);
        break;
      case "send-pin-accept":
        sendPinDecision(true);
        break;
      case "send-pin-decline":
        sendPinDecision(false);
        break;
      case "send-cancel":
        cancelSend();
        break;
      case "leave-send":
        leaveSend();
        break;
      case "send-another":
        sendAnother();
        break;
      case "send-retry":
        retrySend();
        break;
      case "send-finish":
        finishSend();
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

  const fileInput = $("[data-file-input]");
  if (fileInput) {
    fileInput.addEventListener("change", () => {
      const files = Array.from(fileInput.files || []);
      fileInput.value = "";
      uploadSendFiles(files);
    });
  }

  const dropZone = $("[data-send-dropzone]");
  if (dropZone) {
    for (const type of ["dragenter", "dragover"]) {
      dropZone.addEventListener(type, (event) => {
        event.preventDefault();
        dropZone.classList.add("is-dragging");
      });
    }
    for (const type of ["dragleave", "drop"]) {
      dropZone.addEventListener(type, (event) => {
        event.preventDefault();
        dropZone.classList.remove("is-dragging");
      });
    }
    dropZone.addEventListener("drop", (event) => {
      uploadSendFiles(event.dataTransfer && event.dataTransfer.files);
    });
  }

  if (PAGE === "send") {
    for (const type of ["dragover", "drop"]) {
      document.addEventListener(type, (event) => {
        event.preventDefault();
      });
    }
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
