// Surveyor, local browser page. Served by the session's own bridge on 127.0.0.1; talks only to it.
//
// One rule governs this file: it builds TEXT NODES. Nothing received — the assistant's words, a patent
// title, a dialog — is ever parsed as markup, turned into a link, or used as a resource address. The agent
// has no network; this page runs in a browser that does, so it must never become the agent's way out.
// tests/test_surveyor_web.py greps this file for the constructs that would break that rule.
"use strict";

(() => {
  const KEY_STORE = "surveyor-session-key";
  const $ = (id) => document.getElementById(id);

  // ── the session key: from the URL fragment (never sent to a server), then out of the address bar ──
  let key = "";
  const frag = new URLSearchParams(location.hash.slice(1));
  if (frag.get("k")) {
    key = frag.get("k");
    try { sessionStorage.setItem(KEY_STORE, key); } catch (_) { /* private mode: keep it in memory */ }
    history.replaceState(null, "", location.pathname);
  } else {
    try { key = sessionStorage.getItem(KEY_STORE) || ""; } catch (_) { key = ""; }
  }

  const { el, clear, markdown } = window.SurveyorUI;

  // ── talking to the bridge ──
  async function api(path, body) {
    const res = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: Object.assign({ authorization: `Bearer ${key}` }, body === undefined ? {} : { "content-type": "application/json" }),
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    let data = {};
    try { data = await res.json(); } catch (_) { data = {}; }
    if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
    return data;
  }

  const recentToasts = new Map();   // message → element, so a repeated notice is shown once
  function toast(message, level) {
    const text = String(message || "");
    if (recentToasts.has(text)) return;
    const t = el("div", `toast ${level || "info"}`, text);
    $("toasts").append(t);
    recentToasts.set(text, t);
    setTimeout(() => { t.remove(); recentToasts.delete(text); }, level === "error" ? 12000 : 7000);
  }

  // Back to the home page that started this session. Same rule as the home page's own opener: only an
  // address this computer made (a local page with its key), never anything from the conversation.
  const HOME_LINK = /^http:\/\/127\.0\.0\.1:\d{2,5}\/#k=[A-Za-z0-9_-]{20,}(&r=[A-Za-z0-9_%./-]*)?$/;
  let homeUrl = "";
  let matterId = "";
  // `route`: open the home page straight at a page of it (its own address, with its own key).
  function goHome(route) {
    const url = route ? `${homeUrl}&r=${encodeURIComponent(route)}` : homeUrl;
    if (!HOME_LINK.test(url)) { toast("This session was started from a terminal, so there is no home page to return to.", "info"); return; }
    window.open(url, "_blank", "noopener,noreferrer");
  }
  // Every way out of a finished session, in one place, so a session is never a dead end: back to the
  // matter (where another session is one click), back to home, or — with no home page — the command.
  function wayOut(parent) {
    const row = el("div", "row ended-actions");
    if (HOME_LINK.test(homeUrl)) {
      const again = el("button", "primary", "Start another session on this matter");
      const home = el("button", "ghost", "Surveyor home");
      again.type = home.type = "button";
      again.addEventListener("click", () => goHome(`/matter/${matterId}`));
      home.addEventListener("click", () => goHome(""));
      row.append(again, home);
    } else {
      const cmd = `ir surveyor open ${matterId} --web`;
      const copy = el("button", "ghost small", "Copy the command");
      copy.type = "button";
      copy.addEventListener("click", () => navigator.clipboard.writeText(cmd).then(() => toast("Copied.", "info")).catch(() => {}));
      row.append(el("span", "sub", "Start another session with: "), el("span", "mono", cmd), copy);
    }
    parent.append(row);
  }

  // ── trust panel ──
  const SYM = { ok: "✓", warn: "◐", fail: "✗", off: "○", info: "●" };
  const VERDICT_PILL = { private: "🔒 Private", limited: "◐ Partly protected", blocked: "⛔ Not opened" };

  function renderTrust(t) {
    const body = $("trust-body");
    clear(body);
    const pill = $("verdict");
    pill.className = `pill pill-${t.verdict}`;
    pill.textContent = VERDICT_PILL[t.verdict] || t.verdict;
    body.append(el("div", `verdict ${t.verdict}`, t.headline));
    body.append(el("p", "explainer", t.explainer || ""));
    body.append(el("h2", "", "What protects this matter"));
    for (const it of t.items || []) {
      const head = el("div", "item-head",
        el("span", `sym ${it.state}`, SYM[it.state] || "·"),
        el("span", "item-title", it.title),
        el("span", "item-summary", it.summary));
      if (it.points && it.points.length) head.append(el("ul", "item-points", ...it.points.map((p) => el("li", "", p))));
      const hasMore = (it.more && it.more.length) || (it.technical && it.technical.length);
      if (hasMore) {
        const more = el("div", "more");
        more.hidden = true;
        for (const p of it.more || []) more.append(el("p", "", p));
        if (it.technical && it.technical.length) {
          const table = el("table", "tech");
          for (const r of it.technical) {
            table.append(el("tr", "", el("td", `sym ${r.ok ? "ok" : "fail"}`, r.ok ? "✓" : "✗"),
              el("td", "", el("div", "", r.label), el("div", "v", r.value))));
          }
          more.append(el("p", "", `Technical detail (${it.technical.length})`), table);
        }
        const toggle = el("button", "more-toggle", "More");
        toggle.type = "button";
        toggle.setAttribute("aria-expanded", "false");
        toggle.addEventListener("click", () => {
          more.hidden = !more.hidden;
          toggle.textContent = more.hidden ? "More" : "Less";
          toggle.setAttribute("aria-expanded", String(!more.hidden));
        });
        head.append(toggle, more);
      }
      body.append(el("div", "item", head));
    }
    body.append(el("h2", "", "What this can't prove"));
    body.append(el("ul", "limits", ...(t.limits || []).map((l) => el("li", "", l))));
    body.append(el("div", "checked", `Checked ${new Date(t.checked_at).toLocaleString([], { dateStyle: "medium", timeStyle: "short", hour12: false })}`));
  }

  // ── conversation ──
  const log = $("log");
  let current = null;       // the assistant message being streamed: {node, text}
  let renderQueued = false;
  const cards = new Map();  // toolCallId → card elements
  const marks = new Map();  // publication number → mark value
  const docRows = new Map(); // publication number → [row button groups]
  let busy = false;
  let ended = false;
  let toolRunning = "";

  function stick() {
    const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 160;
    return () => { if (nearBottom) log.scrollTop = log.scrollHeight; };
  }
  function hideWelcome() { $("empty").hidden = true; }

  function addUser(text) {
    hideWelcome();
    clearNext();
    const s = stick();
    log.append(el("div", "msg msg-user", text));
    s();
  }

  function assistantStart() {
    hideWelcome();
    const node = el("div", "msg msg-assistant");
    log.append(node);
    current = { node, text: "" };
  }
  function renderCurrent() {
    renderQueued = false;
    if (!current) return;
    const s = stick();
    clear(current.node);
    current.node.append(markdown(current.text));
    s();
  }
  function assistantDelta(text) {
    if (!current) assistantStart();
    current.text += text;
    if (!renderQueued) { renderQueued = true; requestAnimationFrame(renderCurrent); }
  }
  function assistantEnd(ev) {
    if (!current) assistantStart();
    current.text = ev.text || "";
    renderCurrent();
    if (!current.text.trim()) current.node.remove();
    if (ev.stopped === "error") showError(ev.error || "");
    if (ev.stopped === "aborted") log.append(el("div", "step", "Stopped."));
    current = null;
  }

  // An error from the AI's side, said plainly, with the raw detail one click away. The same error repeated
  // (the agent retries) updates one line instead of stacking.
  let lastError = null;
  function plainModelError(detail) {
    const d = detail.toLowerCase();
    if (d.includes("nonce")) return "The AI machine turned this request away because its one-time key had expired. Try again; a fresh key is fetched automatically.";
    if (d.includes("429") || d.includes("rate")) return "The AI machine is busy right now. Wait a moment and try again.";
    if (d.includes("unreachable") || d.includes("502") || d.includes("503")) return "The AI machine couldn't be reached. Nothing was sent in the clear; try again in a minute.";
    if (d.includes("not verified") || d.includes("refus")) return "The AI machine could not be verified, so nothing was sent to it.";
    return "The AI machine didn't answer this request.";
  }
  function showError(detail) {
    const plain = plainModelError(detail);
    if (lastError && lastError.plain === plain && lastError.node.isConnected && log.lastElementChild === lastError.node) {
      lastError.count += 1;
      lastError.counter.textContent = ` (${lastError.count} times)`;
      return;
    }
    const counter = el("span", "count", "");
    const more = el("details", "err-detail", el("summary", "", "Technical detail"), el("div", "mono", detail));
    const node = el("div", "msg-error", el("div", "", plain, counter), detail ? more : null);
    log.append(node);
    lastError = { plain, node, counter, count: 1 };
  }

  const STEP_TEXT = {
    read: (a) => `Read ${String(a.path || "").split("/").pop() || "a file"}`,
    ls: () => "Looked at the matter folder",
    find: () => "Searched the matter folder for files",
    grep: (a) => `Searched the matter folder for “${a.pattern || ""}”`,
    edit: (a) => `Edited ${String(a.path || "").split("/").pop()}`,
    matter_marks: () => "Read your relevance marks",
    write: (a) => `Wrote ${String(a.path || "").split("/").pop()}`,
  };

  // Once something in a card is marked relevant, offer the obvious next move in one click.
  // Every button sends exactly the words it shows.
  const DEEPER = "Look deeper at the ones I marked relevant: search their features one at a time and find documents like them";
  const LEAVE_OUT = "Continue the survey, leaving out what I marked known or not relevant";
  function offerDeeper(card) {
    if (!card || card.querySelector(".deeper") || ended) return;
    const b = el("button", "deeper", DEEPER);
    b.type = "button";
    b.addEventListener("click", () => { b.remove(); send(DEEPER); });
    card.append(el("div", "card-actions", b));
  }

  // "From your marks": next steps built here, from the marks alone, so they change the moment a mark does.
  // No call to the assistant and nothing hidden in the conversation; the assistant's own suggestions sit
  // in the conversation, these sit above the message box.
  const markOrder = [];                     // publication numbers, most recently marked first
  function noteMarked(keyNo) {
    const i = markOrder.indexOf(keyNo);
    if (i >= 0) markOrder.splice(i, 1);
    markOrder.unshift(keyNo);
  }
  // When nothing is marked yet the welcome's suggestions are gone as soon as the first message is sent, and
  // the professional is left with an empty box and no idea what this thing takes. The bar always offers
  // something: their marks when they have any, plain ideas when they do not.
  const IDEAS = ["Run a prior-art survey of the disclosure",
                 "Search one feature of the disclosure on its own",
                 "Summarise what the searches have surfaced so far"];
  function renderMarkSteps() {
    const bar = $("mark-steps");
    const list = $("mark-steps-list");
    clear(list);
    const relevant = markOrder.filter((k) => marks.get(k) === "relevant");
    for (const k of Array.from(marks.keys())) if (marks.get(k) === "relevant" && !relevant.includes(k)) relevant.push(k);
    const excluded = Array.from(marks.values()).some((v) => v === "known" || v === "not-relevant");
    const steps = [];
    if (relevant.length) steps.push(DEEPER);
    for (const k of relevant.slice(0, 2)) steps.push(`Find documents like ${k}`);
    if (excluded) steps.push(LEAVE_OUT);
    const fromMarks = steps.length > 0;
    for (const step of (fromMarks ? steps : IDEAS)) {
      const b = el("button", "", step);
      b.type = "button";
      b.addEventListener("click", () => send(step));
      list.append(b);
    }
    bar.querySelector(".next-title").textContent = fromMarks ? "From your marks" : "Ideas";
    bar.hidden = ended;
  }

  // Next steps offered by the assistant: each button shows exactly the message it sends. Shown when the
  // assistant has finished, cleared when a new message goes out.
  let pendingNext = [];
  function clearNext() {
    for (const n of Array.from(document.querySelectorAll(".next"))) n.remove();
  }
  function renderNext() {
    if (!pendingNext.length || ended) return;
    clearNext();
    const row = el("div", "next", el("div", "next-title", "Next steps"));
    for (const step of pendingNext) {
      const b = el("button", "", step);
      b.type = "button";
      b.addEventListener("click", () => { clearNext(); send(step); });
      row.append(b);
    }
    pendingNext = [];
    const s = stick();
    log.append(row);
    s();
  }

  function markButtons(keyNo, card) {
    const wrap = el("div", "marks");
    const opts = [["relevant", "Relevant"], ["not-relevant", "Not relevant"], ["known", "Known"]];
    const buttons = opts.map(([value, label]) => {
      const b = el("button", `m-${value}`, label);
      b.type = "button";
      b.setAttribute("aria-pressed", String(marks.get(keyNo) === value));
      b.title = `Mark ${keyNo} as ${label.toLowerCase()} (your judgement, kept with the matter)`;
      b.addEventListener("click", async () => {
        try {
          await api("/api/mark", { key: keyNo, mark: value });
          marks.set(keyNo, value);
          noteMarked(keyNo);
          refreshMarks(keyNo);
          renderMarkSteps();
          toast(`Saved: ${keyNo} marked ${label.toLowerCase()}.`, "info");
          if (value === "relevant") offerDeeper(card);
        } catch (e) { toast(`Couldn't record the mark: ${e.message}`, "error"); }
      });
      wrap.append(b);
      return [value, b];
    });
    if (!docRows.has(keyNo)) docRows.set(keyNo, []);
    docRows.get(keyNo).push(buttons);
    return wrap;
  }
  function refreshMarks(keyNo) {
    for (const group of docRows.get(keyNo) || []) {
      for (const [value, b] of group) b.setAttribute("aria-pressed", String(marks.get(keyNo) === value));
    }
  }

  function toolStart(ev) {
    hideWelcome();
    const s = stick();
    if (ev.tool === "suggest_next_steps") {
      return;
    }
    if (ev.tool === "prior_art_search") {
      const a = ev.args || {};
      const card = el("div", "card");
      const sub = el("span", "sub", "checking the search machine…");
      const title = el("span", "title", "🔍 Sealed patent search");
      const what = a.feature ? el("span", "what", `feature: ${a.feature}`) : a.like ? el("span", "what", `documents like ${String(a.like).toUpperCase()}`) : null;
      card.append(el("div", "card-head", title, what, sub));
      const q = String(a.text || "");
      if (q) card.append(el("div", "card-query", q.length > 320 ? `${q.slice(0, 320)}…` : q));
      log.append(card);
      cards.set(ev.call, { card, sub, title });
      toolRunning = "Searching the patent database in its sealed machine…";
    } else {
      const fn = STEP_TEXT[ev.tool];
      const step = el("div", "step", el("span", "step-dot", "·"), el("span", "", fn ? fn(ev.args || {}) : `Used ${ev.tool}`));
      log.append(step);
      toolRunning = fn ? `${fn(ev.args || {})}…` : "Working…";
    }
    updateActivity();
    s();
  }

  function plainRefusal(text) {
    const t = String(text || "").toLowerCase();
    if (t.includes("declined")) return "You didn't allow this search, so nothing was sent.";
    if (t.includes("did not answer") || t.includes("unreachable") || t.includes("timed out")) return "The search machine isn't answering, so nothing was sent. It may not be running right now.";
    return `The search was not sent: ${text}`;
  }

  function toolEnd(ev) {
    toolRunning = "";
    updateActivity();
    if (ev.tool === "suggest_next_steps") {
      const steps = ev.ok && ev.details && Array.isArray(ev.details.steps) ? ev.details.steps : [];
      pendingNext = steps.map(String).filter((t) => t && !/^[\/!]/.test(t)).slice(0, 4);
      if (!busy) renderNext();
      return;
    }
    if (ev.tool !== "prior_art_search") return;
    const entry = cards.get(ev.call);
    if (!entry) return;
    const { card, sub, title } = entry;
    if (ev.details && ev.details.searchNo) title.textContent = `🔍 Sealed patent search ${ev.details.searchNo}`;
    const d = ev.details || {};
    const s = stick();
    // The assistant's own parameter slip (no text, or `like` on a document it never got back): nothing was
    // verified or sent, and it retries. Say so quietly instead of showing a red refusal the professional
    // might read as a problem with the search machine. Any other failure keeps the red card.
    const slip = /needs a self-contained description|was not returned by a search in this session/.test(String(ev.text || ""));
    if (!ev.ok && slip) {
      card.replaceWith(el("div", "step", el("span", "step-dot", "·"), el("span", "", "The assistant's search request was incomplete, so nothing was sent; it corrected it.")));
      cards.delete(ev.call);
      return;
    }
    if (!ev.ok || !d.ok) {
      sub.textContent = "not sent";
      card.append(el("div", "card-note bad", plainRefusal(ev.text || d.refusal)));
      s();
      return;
    }
    const docs = Array.isArray(d.docs) ? d.docs : [];
    const again = docs.filter((d) => d.alsoIn).length;
    sub.textContent = `${docs.length} documents${again ? ` (${again} already seen)` : ""} · opened on this computer only`;
    if (d.testRoots) card.append(el("div", "card-note warn", "TEST machine: checked against test keys, not a real verification."));
    else card.append(el("div", "card-note", `🔒 ${d.ours ? "InferRoute's sealed search machine" : "Sealed search machine"}, checked just before the search. Only that machine could read the query.`));
    const list = el("ol", "docs");
    docs.forEach((doc, idx) => {
      const keyNo = String(doc.key || "");
      const title = el("div", "dtitle", String(doc.title || ""));
      const row = el("li", "doc",
        el("span", "rank", String(idx + 1)),
        el("div", "", el("span", "key", keyNo), doc.year ? el("span", "year", String(doc.year)) : null,
          doc.alsoIn ? el("span", "seen", `also in search ${doc.alsoIn}`) : null, title),
        markButtons(keyNo, card));
      title.addEventListener("click", () => row.classList.toggle("open"));
      list.append(row);
    });
    card.append(list);
    card.append(el("div", "card-foot", "Mark what matters: saved as you click, kept with the matter. The assistant can read your marks to steer its next searches, but can't make or change them. A search finds related documents; it doesn't prove novelty."));
    if (docs.some((d) => marks.get(String(d.key)) === "relevant")) offerDeeper(card);
    s();
  }

  function updateActivity() {
    const a = $("activity");
    a.hidden = !(busy || toolRunning) || ended;
    $("activity-text").textContent = toolRunning || "The assistant is working…";
    $("input").placeholder = busy ? "The assistant is working. Anything you send now is delivered when it finishes."
      : "Ask the assistant about this matter…";
    $("stop").hidden = !busy || ended;
  }

  // Write the invention without leaving the session: the file lives in the matter's folder on this computer,
  // and being told a path to go and edit is not an answer when the assistant is waiting for it.
  async function disclosureDialog() {
    let current = "";
    try { current = (await api("/api/disclosure")).text; } catch (e) { toast(e.message, "error"); return; }
    const box = document.createElement("textarea");
    box.rows = 14;
    box.value = current;
    box.placeholder = "Describe the invention in plain technical terms.";
    const err = el("p", "form-error");
    const save = el("button", "primary", "Save");
    const cancel = el("button", "ghost", "Cancel");
    save.type = cancel.type = "button";
    cancel.addEventListener("click", () => { $("dialog").hidden = true; });
    save.addEventListener("click", async () => {
      try {
        const r = await api("/api/disclosure", { text: box.value });
        $("dialog").hidden = true;
        toast(`Disclosure saved (${r.words} words). Ask for a prior-art survey when you are ready.`, "info");
        const line = $("disclosure-line");
        line.classList.remove("warn");
        line.textContent = `The disclosure is in the matter folder: disclosure.md, ${r.words} words.`;
        for (const n of Array.from(document.querySelectorAll(".disclosure-actions"))) n.remove();
      } catch (e) { err.textContent = e.message; }
    });
    $("dialog-title").textContent = "Disclosure";
    const body = $("dialog-body");
    clear(body);
    body.append(el("p", "", "The invention, as the assistant will read it. It stays on this computer; only its sealed searches leave, encrypted."), box, err);
    const actions = $("dialog-actions");
    clear(actions);
    actions.append(cancel, save);
    $("dialog").hidden = false;
    setTimeout(() => box.focus(), 0);
  }

  // ── dialogs (the approval before a search) ──
  let openDialog = null;
  function showDialog(ev) {
    openDialog = ev;
    $("dialog-title").textContent = ev.title || "The assistant needs your answer";
    const body = $("dialog-body");
    clear(body);
    // The approval message is plain text from this computer's extension. Show the quoted search text as a
    // quote and the technical line small; everything else as paragraphs.
    const lines = String(ev.message || "").split("\n");
    let para = [];
    const flush = () => { if (para.length) { body.append(el("p", "", para.join(" "))); para = []; } };
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) { flush(); continue; }
      if (/^".*"$/.test(line) || (/^"/.test(line) && line.length > 40)) { flush(); body.append(el("blockquote", "", line.replace(/^"|"$/g, ""))); continue; }
      if (line.startsWith("(technical:")) { flush(); body.append(el("p", "tech-line", line)); continue; }
      para.push(line);
    }
    flush();
    const actions = $("dialog-actions");
    clear(actions);
    const answer = async (payload) => {
      $("dialog").hidden = true;
      openDialog = null;
      try { await api("/api/dialog", Object.assign({ id: ev.id }, payload)); } catch (e) { toast(e.message, "error"); }
    };
    if (ev.method === "confirm") {
      const no = el("button", "ghost", "Don't allow");
      const yes = el("button", "primary", "Allow");
      no.type = yes.type = "button";
      no.addEventListener("click", () => answer({ confirmed: false }));
      yes.addEventListener("click", () => answer({ confirmed: true }));
      actions.append(no, yes);
      setTimeout(() => yes.focus(), 0);
    } else if (ev.method === "select") {
      for (const opt of ev.options || []) {
        const b = el("button", "", String(opt));
        b.type = "button";
        b.addEventListener("click", () => answer({ value: String(opt) }));
        actions.append(b);
      }
      const cancel = el("button", "ghost", "Cancel");
      cancel.type = "button";
      cancel.addEventListener("click", () => answer({ cancelled: true }));
      actions.append(cancel);
    } else {
      const input = document.createElement("input");
      input.type = "text";
      const ok = el("button", "primary", "OK");
      const cancel = el("button", "ghost", "Cancel");
      ok.type = cancel.type = "button";
      ok.addEventListener("click", () => answer({ value: input.value }));
      cancel.addEventListener("click", () => answer({ cancelled: true }));
      actions.append(input, cancel, ok);
      setTimeout(() => input.focus(), 0);
    }
    $("dialog").hidden = false;
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && openDialog) {
      const ev = openDialog;
      $("dialog").hidden = true;
      openDialog = null;
      api("/api/dialog", ev.method === "confirm" ? { id: ev.id, confirmed: false } : { id: ev.id, cancelled: true }).catch(() => {});
    }
  });

  // ── status bar ──
  const statuses = new Map();
  function renderStatus() {
    const bar = $("statusbar");
    clear(bar);
    for (const k of ["ir-model-enclave", "ir-search-enclave", "ir-enclave-lifecycle"]) {
      if (statuses.get(k)) bar.append(el("span", "", statuses.get(k)));
    }
    bar.hidden = !bar.firstChild;
  }

  function showEnded(summary) {
    ended = true;
    busy = false;
    updateActivity();
    const box = $("ended");
    clear(box);
    const kb = (n) => `${Math.round((Number(n) || 0) / 1024)} KB`;
    const did = Number(summary.requests) > 0;
    box.append(el("div", "", el("b", "", "Session closed. "),
      did ? `${summary.requests} request${summary.requests === 1 ? "" : "s"} to the AI machine · ${kb(summary.sealed_bytes)} encrypted here · plaintext that left this computer: 0 bytes.`
          : "Nothing was asked in this session, so there is nothing to export."));
    box.append(el("div", "", did ? "Export the record to keep it (button on the right), then close this tab."
                                 : "Start another session when you are ready — a session is just a sitting, and the matter keeps everything."));
    wayOut(box);
    box.hidden = false;
    $("composer").hidden = true;
    $("end").hidden = true;
    $("mark-steps").hidden = true;
  }

  function handle(ev) {
    switch (ev.kind) {
      case "user": addUser(ev.text); break;
      case "busy": busy = ev.value; updateActivity(); if (!busy) renderNext(); break;
      case "conversation_kept": $("kept-note").hidden = false; break;
      case "assistant_start": assistantStart(); break;
      case "assistant_delta": assistantDelta(ev.text); break;
      case "assistant_end": assistantEnd(ev); break;
      case "tool_start": toolStart(ev); break;
      case "tool_end": toolEnd(ev); break;
      case "dialog": showDialog(ev); break;
      case "dialog_closed":
        if (openDialog && openDialog.id === ev.id) { $("dialog").hidden = true; openDialog = null; }
        break;
      case "notify": toast(ev.message, ev.level); break;
      case "status": statuses.set(ev.key, ev.text); renderStatus(); break;
      case "trust": renderTrust(ev.trust); break;
      case "ended": showEnded(ev.summary); break;
      default: break;
    }
  }

  // ── the event stream (NDJSON over fetch, so the key rides in a header, never in a URL) ──
  let lastSeq = 0;
  async function stream() {
    while (!ended) {
      try {
        const res = await fetch(`/api/events?after=${lastSeq}`, {
          headers: { authorization: `Bearer ${key}` }, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer",
        });
        if (res.status === 401) { showNoKey(); return; }
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let nl;
          while ((nl = buf.indexOf("\n")) >= 0) {
            const line = buf.slice(0, nl);
            buf = buf.slice(nl + 1);
            if (!line.trim()) continue;
            let ev;
            try { ev = JSON.parse(line); } catch (_) { continue; }
            if (ev.kind === "ping") continue;
            if (typeof ev.seq === "number") { if (ev.seq <= lastSeq) continue; lastSeq = ev.seq; }
            handle(ev);
          }
        }
      } catch (_) { /* the session may be restarting the stream; retry */ }
      if (!ended) await new Promise((r) => setTimeout(r, 1200));
    }
  }

  function showNoKey() {
    $("nokey").hidden = false;
    $("matter").hidden = true;
    $("layout").hidden = true;
    $("verdict").hidden = true;
    $("end").hidden = true;
  }

  // ── composer ──
  async function send(text) {
    const t = String(text || "").trim();
    if (!t || ended) return;
    clearNext();
    $("input").value = "";
    autosize();
    try { await api("/api/prompt", { text: t }); } catch (e) { toast(`Not sent: ${e.message}`, "error"); $("input").value = t; }
  }
  function autosize() {
    const i = $("input");
    i.style.height = "auto";
    i.style.height = `${Math.min(i.scrollHeight, window.innerHeight * 0.4)}px`;
  }

  async function init() {
    if (!key) { showNoKey(); return; }
    let s;
    try { s = await api("/api/session"); } catch (e) { showNoKey(); return; }
    $("layout").hidden = false;
    document.title = `Surveyor · ${s.matter}`;
    $("matter").textContent = String(s.matter || "").replace("/", " / ");
    if (s.date_bound) { $("bound").textContent = s.date_bound; $("bound-wrap").hidden = false; }
    renderTrust(s.trust);
    homeUrl = String(s.home || "");
    matterId = String(s.matter || "");
    if (HOME_LINK.test(homeUrl)) {
      const b = el("button", "ghost", "Surveyor home");
      b.type = "button";
      b.addEventListener("click", () => goHome(""));
      $("top-home").replaceWith(b);
      b.id = "top-home";
    }
    const d = s.disclosure || {};
    $("welcome-title").textContent = `Ready to work on ${String(s.matter || "").replace("/", " / ")}`;
    const line = $("disclosure-line");
    if (d.disclosure_words > 0) {
      line.textContent = `The disclosure is in the matter folder: disclosure.md, ${d.disclosure_words} words.`;
    } else {
      line.classList.add("warn");
      line.textContent = "This matter has no disclosure yet — the assistant has nothing to survey.";
      const write = el("button", "primary", "Write the disclosure");
      write.type = "button";
      write.addEventListener("click", disclosureDialog);
      $("empty").insertBefore(el("div", "row disclosure-actions", write), $("suggestions"));
    }
    const sugg = $("suggestions");
    const ideas = s.search
      ? ["Run a prior-art survey of the disclosure", "Summarise the disclosure's key technical features", "Which features are most likely to have prior art?"]
      : ["Summarise the disclosure's key technical features", "What would a prior-art search need to cover?"];
    for (const idea of ideas) {
      const b = el("button", "", idea);
      b.type = "button";
      b.addEventListener("click", () => send(idea));
      sugg.append(b);
    }
    try {
      const m = await api("/api/marks");
      for (const [k, v] of Object.entries(m.marks || {})) marks.set(k, v);
      renderMarkSteps();
    } catch (_) { /* no search in this session */ }
    renderMarkSteps();
    if (s.ended) showEnded(s.ended);
    stream();
  }

  $("composer").addEventListener("submit", (e) => { e.preventDefault(); send($("input").value); });
  $("input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send($("input").value); }
  });
  $("input").addEventListener("input", autosize);
  $("stop").addEventListener("click", () => api("/api/abort", {}).catch((e) => toast(e.message, "error")));
  $("verdict").addEventListener("click", () => $("trust").scrollIntoView({ behavior: "smooth", block: "start" }));
  $("recheck").addEventListener("click", async () => {
    const b = $("recheck");
    b.disabled = true;
    b.textContent = "Checking…";
    try { const r = await api("/api/recheck", {}); renderTrust(r.trust); toast("Checked again just now.", "info"); }
    catch (e) { toast(`Couldn't check: ${e.message}`, "error"); }
    finally { b.disabled = false; b.textContent = "Check again"; }
  });
  $("export").addEventListener("click", async () => {
    const b = $("export");
    b.disabled = true;
    b.textContent = "Exporting…";
    const out = $("export-result");
    try {
      const r = await api("/api/export", {});
      clear(out);
      const copy = el("button", "small", "Copy folder path");
      copy.type = "button";
      copy.addEventListener("click", () => navigator.clipboard.writeText(r.path).then(() => toast("Copied.", "info")).catch(() => {}));
      out.append(el("div", "", el("b", "", "Record exported."), " It holds the disclosure in plain text: store it like the client file."),
        el("span", "mono", r.path),
        el("div", "", "Open record.html in that folder to read it. Check it on this computer with:"),
        el("span", "mono", r.verify_here),
        el("div", "", "Anyone else can check it without InferRoute's software, from inside that folder (needs Python's cryptography library, version 42 or newer):"),
        el("span", "mono", r.verify_anyone), copy);
      out.hidden = false;
    } catch (e) { toast(e.message, "error"); }
    finally { b.disabled = false; b.textContent = "Export the record"; }
  });
  $("end").addEventListener("click", async () => {
    if (!window.confirm("End this session? The assistant stops; your marks and records stay with the matter.")) return;
    try { await api("/api/end", {}); } catch (e) { toast(e.message, "error"); }
  });

  init();
})();
