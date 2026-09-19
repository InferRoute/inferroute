// Probant, local browser page. Served by the session's own bridge on 127.0.0.1; talks only to it.
//
// One rule governs this file: it builds TEXT NODES. Nothing received — the assistant's words, a patent
// title, a dialog — is ever parsed as markup, turned into a link, or used as a resource address. The agent
// has no network; this page runs in a browser that does, so it must never become the agent's way out.
// tests/test_probant_web.py greps this file for the constructs that would break that rule.
"use strict";

(() => {
  const KEY_STORE = "probant-session-key";
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

  const { el, clear, markdown } = window.ProbantUI;

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
    if (!HOME_LINK.test(url)) { toast("This session was started from a terminal, so it has no home page to go back to. To see all your matters, run: ir probant home", "info"); return; }
    window.open(url, "_blank", "noopener,noreferrer");
  }
  // Every way out of a finished session, in one place, so a session is never a dead end: back to the
  // matter (where another session is one click), back to home, or — with no home page — the command.
  function wayOut(parent) {
    const row = el("div", "row ended-actions");
    if (HOME_LINK.test(homeUrl)) {
      const again = el("button", "primary", "Start another session on this matter");
      const home = el("button", "ghost", "Probant home");
      again.type = home.type = "button";
      again.addEventListener("click", () => goHome(`/matter/${matterId}`));
      home.addEventListener("click", () => goHome(""));
      row.append(again, home);
    } else {
      const cmd = `ir probant open ${matterId} --web`;
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
  let stalled = false;
  let toolRunning = "";

  // One way out that always works, wherever it is offered from. The bridge escalates on its side; here the
  // button must never sit on "Ending…" for ever, so a failure is said out loud.
  async function endSession(button) {
    if (button) { button.disabled = true; button.textContent = "Ending…"; }
    try {
      await api("/api/end", {});
    } catch (e) {
      toast(`Could not end the session: ${e.message}`, "error");
      if (button) { button.disabled = false; button.textContent = "End session"; }
    }
  }

  function stick() {
    const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 160;
    return () => { if (nearBottom) log.scrollTop = log.scrollHeight; };
  }
  function hideWelcome() {
    if ($("empty").hidden) return;
    $("empty").hidden = true;
    renderMarkSteps();            // the welcome's offers are gone: the bar takes over, or the box is empty
  }

  function addUser(text) {
    hideWelcome();
    clearNext();
    const s = stick();
    const node = el("div", "msg msg-user", text);
    log.append(node);
    const short = String(text).replace(/\s+/g, " ").trim();
    outlineAdd({ kind: "you", el: node, label: "You asked", detail: short.length > 110 ? `${short.slice(0, 110)}…` : short });
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
  const SUMMARISE_IDEA = "Summarise what the searches have surfaced so far";
  const IDEAS = ["Run a prior-art survey of the disclosure",
                 "Search one feature of the disclosure on its own",
                 SUMMARISE_IDEA];
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
    // Ideas are about the conversation, so they wait for one. Before the first message the welcome's own
    // suggestions are on screen, and a second row of the same offers only made the page look doubled
    // (Henry, 19 Sep). Steps from your MARKS still show at once: they carry the matter over from an
    // earlier session, which is exactly what a fresh session is for.
    const started = $("empty").hidden;
    if (!fromMarks && !started) { bar.hidden = true; return; }
    // And no idea that presumes something that has not happened: nothing to summarise before a search.
    const ideas = IDEAS.filter((i) => i !== SUMMARISE_IDEA || cards.size > 0);
    for (const step of (fromMarks ? steps : ideas)) {
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
          for (const e of cards.values()) if (e.keys && e.keys.includes(keyNo)) refreshCardSummary(e);
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

  // ── folding searches, and the index down the left ──────────────────────────────────────────────
  //
  // Henry, 18 Sep: by the third search the trace is too expanded to read. A results card is 25 documents
  // long, so the feed becomes a wall and the conversation above it is lost. Two halves of one answer: a
  // search folds to its one-line summary, and an index on the left says where everything is.
  //
  // The rule for folding is "the one you are looking at stays open": a new search folds the finished ones.
  // A card you opened or closed yourself is never folded by us afterwards — the moment we override a
  // deliberate click, the control stops being trustworthy.

  function setCollapsed(entry, on, byUser) {
    if (!entry || !entry.body) return;
    entry.collapsed = !!on;
    if (byUser) entry.byUser = true;
    entry.body.hidden = entry.collapsed;
    entry.card.classList.toggle("collapsed", entry.collapsed);
    entry.toggle.textContent = entry.collapsed ? "▸" : "▾";
    entry.toggle.setAttribute("aria-expanded", String(!entry.collapsed));
    entry.toggle.setAttribute("aria-label", entry.collapsed ? "Expand this search" : "Collapse this search");
    refreshCardSummary(entry);
  }

  function autoCollapse() {
    for (const e of cards.values()) {
      if (!e.byUser && !e.failed && !e.collapsed) setCollapsed(e, true);
    }
  }

  // What the head says when the body is folded away. The document count alone is not enough to fold
  // safely — what you would lose sight of is your own marking, so that goes in the summary.
  function refreshCardSummary(entry) {
    if (!entry || entry.n === undefined) return;
    const marked = entry.keys.filter((k) => marks.get(k)).length;
    const relevant = entry.keys.filter((k) => marks.get(k) === "relevant").length;
    const bits = [`${entry.n} document${entry.n === 1 ? "" : "s"}`];
    if (marked) bits.push(`${marked} marked${relevant ? `, ${relevant} relevant` : ""}`);
    bits.push(entry.collapsed ? "click to open" : "opened on this computer only");
    entry.sub.textContent = bits.join(" · ");
    if (entry.outline) outlineUpdate(entry, relevant ? `${relevant} relevant` : marked ? `${marked} marked` : "");
  }

  // The index. One row per landmark — what you asked, and each search — so a long session stays navigable.
  const outlineRows = [];
  // The index is a list of TURNS, not a flat list of events. What you ask is what you navigate by — you
  // hold the session in your head as "the thing I asked about X" — so each question is a heading and the
  // searches it caused hang under it, smaller and indented. A turn can be folded away entirely.
  let currentTurn = null;

  function outlineAdd(item) {
    const row = el("li", `o-${item.kind}`);
    const link = el("button", "o-link");
    link.type = "button";
    // Two parts, always: a kicker that says WHICH this is, and the description, which is the only thing
    // that tells them apart. "Search 7 · 50 documents" is a row that says nothing — a count is not a
    // description, and it was overwriting the one useful line.
    const kicker = el("span", "o-kicker");
    const which = el("span", "o-which", item.label);
    const note = el("span", "o-note", "");
    note.hidden = true;
    kicker.append(which, note);
    const text = el("span", "o-text", item.detail || "");
    link.append(kicker, text);
    link.addEventListener("click", () => {
      // Jumping to a folded search opens it: being sent to a closed box is not arriving.
      if (item.entry && item.entry.collapsed) setCollapsed(item.entry, false, true);
      item.el.scrollIntoView({ behavior: "smooth", block: "start" });
      for (const r of outlineRows) r.row.classList.toggle("here", r === rec);
    });
    const rec = { row, item, which, note, text };
    if (item.kind === "you") {
      const kids = el("ol", "o-children");
      const fold = el("button", "o-fold", "▾");
      fold.type = "button";
      fold.hidden = true;                       // nothing under it yet; an empty control is a puzzle
      fold.setAttribute("aria-expanded", "true");
      fold.setAttribute("aria-label", "Hide the searches from this question");
      fold.addEventListener("click", (e) => {
        e.stopPropagation();
        const hide = !kids.hidden;
        kids.hidden = hide;
        fold.textContent = hide ? "▸" : "▾";
        fold.setAttribute("aria-expanded", String(!hide));
        fold.setAttribute("aria-label", hide ? "Show the searches from this question" : "Hide the searches from this question");
      });
      // The fold and the link are separate cells of one flex row, never stacked on each other: an absolutely
      // positioned control over text is how a click lands on the wrong thing and how the text gets clipped.
      row.append(el("div", "o-row", fold, link), kids);
      $("outline-list").append(row);
      currentTurn = { kids, fold, n: 0 };
      rec.turn = currentTurn;
    } else {
      row.append(link);
      // A search belongs to the question that caused it. Before any question (a replayed session can start
      // mid-flight), it stands on its own rather than being invented a parent.
      (currentTurn ? currentTurn.kids : $("outline-list")).append(row);
      if (currentTurn) {
        rec.parent = currentTurn;
        currentTurn.n += 1;
        currentTurn.fold.hidden = false;
      }
    }
    $("outline-empty").hidden = true;
    outlineRows.push(rec);
    if (item.entry) item.entry.outline = rec;
    return rec;
  }

  function outlineDrop(entry) {
    const rec = entry && entry.outline;
    if (!rec) return;
    rec.row.remove();
    const i = outlineRows.indexOf(rec);
    if (i >= 0) outlineRows.splice(i, 1);
    if (rec.parent) {
      rec.parent.n -= 1;
      if (rec.parent.n <= 0) rec.parent.fold.hidden = true;
    }
    entry.outline = null;
    if (!outlineRows.length) $("outline-empty").hidden = false;
  }

  // Only the parts that actually change: which search this became, and your marking. The description of
  // what was searched is written once and never overwritten by a count.
  function outlineUpdate(entry, note) {
    const rec = entry && entry.outline;
    if (!rec) return;
    if (entry.searchNo) rec.which.textContent = `Search ${entry.searchNo}`;
    rec.note.textContent = note || "";
    rec.note.hidden = !note;
  }

  // ── how long a search is taking, and which step it is on ──────────────────────────────────────
  //
  // Henry, 19 Sep: "where we have 'checking the search machine…', could we have some sort of progress
  // indicator, or at least a timer, maybe the expected wait?" Measured on 18 Sep: a sealed search, including
  // the full re-check of the machine, takes 0.7–0.9 s. So normally this flashes by; it earns its place when
  // something is slow or stuck, and then the step matters more than the seconds. The clock counts only the
  // MACHINE's time: seconds you spend reading the approval prompt are yours, and counting them would turn
  // "slower than usual" into "you were reading".
  // Expectations come from what this computer has measured (probant_timing): per step, per depth — a broad
  // search takes about four times as long as a quick one — and each number says what it measures. Before
  // there is enough data for a step, the view says so rather than inventing a figure.
  let searchTiming = null;
  let clockSkew = 0;                    // server clock minus this page's; the stamps are the server's
  const serverNow = () => Date.now() + clockSkew;
  const PHASE_TEXT = { verifying: "checking the search machine", approval: "waiting for your approval",
                       searching: "searching the sealed index" };
  const DEPTH_K = { quick: 10, standard: 25, broad: 50 };
  const bucketOf = (args) => {
    const k = Number(args && args.k) || DEPTH_K[(args && args.depth) || "quick"] || 10;
    return k > 25 ? "broad" : "quick";
  };

  function machineMs(entry, now) {
    const pending = entry.phase === "approval" ? now - entry.phaseAt : 0;
    return now - entry.startedAt - entry.approvalMs - pending;
  }
  function fmtSeconds(ms) {
    const s = ms / 1000;
    if (s < 10) return `${s.toFixed(1)} s`;
    const r = Math.round(s);
    return r < 60 ? `${r} s` : `${Math.floor(r / 60)} min ${r % 60} s`;
  }
  // What to expect for the step in progress. `null` when nothing measured yet.
  function expectation(entry) {
    const t = searchTiming || {};
    if (entry.phase === "verifying") return t.verifying ? { ...t.verifying, what: "usually" } : null;
    if (entry.phase === "searching") {
      const s = (t.searching || {})[entry.bucket];
      if (!s) return null;
      return { ...s, what: s.source === "machine" ? "the machine itself usually takes" : "usually" };
    }
    return null;
  }
  function paintProgress(entry) {
    if (!entry || entry.done) return;
    if (entry.phase === "approval") {
      entry.sub.textContent = "waiting for your approval";
      entry.sub.classList.remove("slow");
      return;
    }
    const now = serverNow();
    const inStep = now - entry.phaseAt;
    const x = expectation(entry);
    const depth = entry.phase === "searching" ? ` for a ${entry.bucket} search` : "";
    // Slower than usual: past twice the 90th percentile of this step, never under three seconds. With no data,
    // only a generous fixed line — a stall notice is the watchdog's job, not a guess made here.
    const limit = x ? Math.max(3000, 2 * x.p90_ms) : 15000;
    const slow = inStep >= limit;
    let hint;
    if (slow) hint = x ? `slower than usual (${x.what} ${fmtSeconds(x.median_ms)}${depth})` : "taking a while";
    else if (x) hint = `${x.what} ${fmtSeconds(x.median_ms)}${depth} · ${x.n} searches`;
    else hint = "no timings on this computer yet";
    entry.sub.textContent = `${PHASE_TEXT[entry.phase] || PHASE_TEXT.verifying}… ${fmtSeconds(machineMs(entry, now))} · ${hint}`;
    entry.sub.classList.toggle("slow", slow);
  }
  function setPhase(entry, phase, at) {
    if (!entry || entry.done || !PHASE_TEXT[phase]) return;
    const when = at || serverNow();
    if (entry.phase === "approval") entry.approvalMs += when - entry.phaseAt;
    entry.phase = phase;
    entry.phaseAt = when;
    toolRunning = phase === "approval" ? "Waiting for your approval…" : `${PHASE_TEXT[phase][0].toUpperCase()}${PHASE_TEXT[phase].slice(1)}…`;
    updateActivity();
    paintProgress(entry);
  }
  // One clock for every running search, rather than a timer each that could outlive its card.
  setInterval(() => {
    for (const e of cards.values()) if (!e.done && e.startedAt) paintProgress(e);
    paintActivityTime();
  }, 500);

  // "Also in" names the earlier search by what it was about, not by a number you would have to go and look up.
  // A number is what is left only when the earlier search is not on this page.
  const searchesByNo = new Map();       // search number → its card entry
  function seenIn(no) {
    const e = searchesByNo.get(no);
    const about = e && e.about ? e.about : "";
    if (!about) return el("span", "seen", `also in search ${no}`);
    const short = about.length > 42 ? `${about.slice(0, 41).trimEnd()}…` : about;
    const tag = el("span", "seen", `also in ‘${short}’`);
    tag.title = `Also returned by search ${no}: ${about}`;
    return tag;
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
      // A real button carries the state for a screen reader and the keyboard; the whole head is also a
      // click target, because a 12px chevron is not one.
      const toggle = el("button", "card-toggle", "▾");
      toggle.type = "button";
      toggle.setAttribute("aria-expanded", "true");
      toggle.setAttribute("aria-label", "Collapse this search");
      const head = el("div", "card-head", toggle, title, what, sub);
      card.append(head);
      const body = el("div", "card-body");
      const q = String(a.text || "");
      if (q) body.append(el("div", "card-query", q.length > 320 ? `${q.slice(0, 320)}…` : q));
      card.append(body);
      // Timed from the SERVER's stamp on the event: a reload replays history, and a clock started on receipt
      // would restart every running search at zero.
      const t0 = ev.at || serverNow();
      const entry = { card, sub, title, body, toggle, head, keys: [], collapsed: false, byUser: false,
                      startedAt: t0, phase: "verifying", phaseAt: t0, approvalMs: 0, done: false,
                      bucket: bucketOf(a) };
      const flip = (e) => { if (e) e.stopPropagation(); setCollapsed(entry, !entry.collapsed, true); };
      toggle.addEventListener("click", flip);
      // Clicking the head also folds — but NOT when you were selecting its text. Dragging across the
      // query to copy it ended with the card slamming shut, which is the same click doing two jobs.
      head.addEventListener("click", (e) => {
        const sel = window.getSelection && window.getSelection();
        if (sel && !sel.isCollapsed && head.contains(sel.anchorNode)) return;
        flip(e);
      });
      // Earlier searches fold away as soon as a new one starts: by the third search the feed is unreadable,
      // and what you want on screen is the one running now.
      autoCollapse();
      log.append(card);
      cards.set(ev.call, entry);
      // What this search was ABOUT, in the words it was run with — how it is named everywhere else on the
      // page (Henry, 19 Sep: "instead of 'also in search 2' let's say also in 'Routing by permission'").
      entry.about = a.feature ? String(a.feature) : a.like ? `documents like ${String(a.like).toUpperCase()}` : q.replace(/\s+/g, " ").trim();
      outlineAdd({ kind: "search", el: card, label: "Search", detail: a.feature ? `feature: ${a.feature}` : a.like ? `like ${String(a.like).toUpperCase()}` : q.slice(0, 60), entry });
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
    const { card, sub, title, body } = entry;
    entry.done = true;                  // the clock stops; the bridge records the wait for the statistics
    sub.classList.remove("slow");
    if (ev.details && ev.details.searchNo) {
      title.textContent = `🔍 Sealed patent search ${ev.details.searchNo}`;
      entry.searchNo = ev.details.searchNo;
      searchesByNo.set(entry.searchNo, entry);
    }
    const d = ev.details || {};
    const s = stick();
    // The assistant's own parameter slip (no text, or `like` on a document it never got back): nothing was
    // verified or sent, and it retries. Say so quietly instead of showing a red refusal the professional
    // might read as a problem with the search machine. Any other failure keeps the red card.
    const slip = /needs a self-contained description|was not returned by a search in this session/.test(String(ev.text || ""));
    if (!ev.ok && slip) {
      card.replaceWith(el("div", "step", el("span", "step-dot", "·"), el("span", "", "The assistant's search request was incomplete, so nothing was sent; it corrected it.")));
      cards.delete(ev.call);
      outlineDrop(entry);          // the card is gone; an index row pointing at a detached node goes nowhere
      return;
    }
    if (!ev.ok || !d.ok) {
      sub.textContent = "not sent";
      body.append(el("div", "card-note bad", plainRefusal(ev.text || d.refusal)));
      setCollapsed(entry, false);                 // a refusal is short and worth reading; never fold it away
      entry.failed = true;
      outlineUpdate(entry, "not sent");
      s();
      return;
    }
    const docs = Array.isArray(d.docs) ? d.docs : [];
    const again = docs.filter((d) => d.alsoIn).length;
    sub.textContent = `${docs.length} documents${again ? ` (${again} already seen)` : ""} · opened on this computer only`;
    if (d.testRoots) body.append(el("div", "card-note warn", "TEST machine: checked against test keys, not a real verification."));
    else body.append(el("div", "card-note", `🔒 ${d.ours ? "InferRoute's sealed search machine" : "Sealed search machine"}, checked just before the search. Only that machine could read the query.`));
    const list = el("ol", "docs");
    docs.forEach((doc, idx) => {
      const keyNo = String(doc.key || "");
      const title = el("div", "dtitle", String(doc.title || ""));
      const row = el("li", "doc",
        el("span", "rank", String(idx + 1)),
        el("div", "", el("span", "key", keyNo), doc.year ? el("span", "year", String(doc.year)) : null,
          doc.alsoIn ? seenIn(doc.alsoIn) : null, title),
        markButtons(keyNo, card));
      title.addEventListener("click", () => row.classList.toggle("open"));
      list.append(row);
    });
    body.append(list);
    body.append(el("div", "card-foot", "Mark what matters: saved as you click, kept with the matter. The assistant can read your marks to steer its next searches, but can't make or change them. A search finds related documents; it doesn't prove novelty."));
    if (docs.some((d) => marks.get(String(d.key)) === "relevant")) offerDeeper(card);
    entry.keys = docs.map((doc) => String(doc.key || ""));
    entry.n = docs.length;
    refreshCardSummary(entry);
    outlineUpdate(entry, "");            // the description stays; the count lives in the card head
    renderMarkSteps();                   // a search now exists, so "summarise what they surfaced" makes sense
    s();
  }

  // Two clocks on the activity bar (Henry, 19 Sep: "a timer, so we know when it started processing something
  // new"): how long the CURRENT step has run — it restarts whenever the assistant moves on to something new,
  // thinking, a search, a prompt for you — and, once that differs, how long since you asked. Both from the
  // server's stamps on the events, so a reload shows the true times instead of starting again at zero.
  let turnAt = null;                    // when the assistant took up your message
  let stepAt = null;                    // when the step now on the bar began
  let stepText = "";
  let lastEventAt = null;               // the stamp of the event being handled
  function fmtWhole(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, "0")} s`;
  }
  function paintActivityTime() {
    const t = $("activity-time");
    if ($("activity").hidden || stepAt === null) { t.textContent = ""; return; }
    const now = serverNow();
    const whole = turnAt !== null && stepAt - turnAt > 1000 ? ` · ${fmtWhole(now - turnAt)} since you asked` : "";
    t.textContent = `${fmtWhole(now - stepAt)}${whole}`;
  }
  function updateActivity() {
    const a = $("activity");
    a.hidden = !(busy || toolRunning) || ended || stalled;
    const text = toolRunning || "The assistant is working…";
    if (text !== stepText) { stepText = text; stepAt = lastEventAt || serverNow(); }
    $("activity-text").textContent = text;
    paintActivityTime();
    $("input").placeholder = stalled ? "Stop the current attempt before sending anything else."
      : busy ? "The assistant is working. Anything you send now is delivered when it finishes."
      : "Ask the assistant about this matter…";
    $("stop").hidden = !busy || ended || stalled;
  }

  // The assistant has said nothing at all for two minutes, mid-answer. Say that plainly — a spinner that
  // never stops is a worse answer than bad news — and give both real ways forward. Nothing here is lost:
  // every search and mark is already recorded with the matter on this computer.
  function showStalled(on, seconds) {
    stalled = on;
    const box = $("stalled");
    box.hidden = !on || ended;
    clear(box);
    updateActivity();
    if (!on || ended) return;
    const mins = Math.max(1, Math.round((Number(seconds) || 120) / 60));
    box.append(el("div", "stalled-title", "The assistant has stopped answering."));
    box.append(el("p", "", `Nothing has come back from the sealed AI machine for ${mins} minute${mins === 1 ? "" : "s"}, `
      + "part-way through an answer. This is a fault on our side, not something you did."));
    box.append(el("p", "sub", "Your searches and your marks are already saved with the matter, and the record can "
      + "still be exported. Starting again costs you the last answer only."));
    const row = el("div", "row");
    const stop = el("button", "primary", "Stop this attempt and carry on");
    const finish = el("button", "ghost", "End the session and keep the record");
    stop.type = finish.type = "button";
    stop.addEventListener("click", async () => {
      stop.disabled = true;
      stop.textContent = "Stopping…";
      let settled = false;
      try { settled = (await api("/api/abort", {})).settled === true; } catch (_) { settled = false; }
      if (settled) { showStalled(false); toast("Stopped. You can ask again.", "info"); return; }
      stop.hidden = true;
      box.append(el("p", "warn", "It would not stop. Ending the session is the way out — the matter keeps "
        + "everything, and you can start another session on it straight away."));
    });
    finish.addEventListener("click", () => endSession(finish));
    row.append(stop, finish);
    box.append(row);
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
    cancel.addEventListener("click", () => { $("dialog").hidden = true; showNextDialog(); });
    save.addEventListener("click", async () => {
      try {
        const r = await api("/api/disclosure", { text: box.value });
        $("dialog").hidden = true;
        showNextDialog();
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
  // Prompts from the assistant wait in line. The page has ONE dialog, and a second prompt used to REPLACE the
  // first on screen — and a prompt nobody can see is a search that waits for ever. 19 Sep, caught by the
  // event recorder: five parallel searches raised five approval prompts within 10 ms; the last was answered
  // and ran at once; the other four hung at "waiting for your approval" with nothing left to click. The same
  // shape was the unexplained stall of 18 Sep.
  const dialogQueue = [];
  function queueDialog(ev) {
    if ((openDialog && openDialog.id === ev.id) || dialogQueue.some((d) => d.id === ev.id)) return;
    dialogQueue.push(ev);
    showNextDialog();
  }
  function showNextDialog() {
    // One at a time — and not over the disclosure editor, which borrows the same dialog.
    if (openDialog || !$("dialog").hidden || ended) return;
    const next = dialogQueue.shift();
    if (next) showDialog(next);
  }
  function dropDialog(id) {
    const i = dialogQueue.findIndex((d) => d.id === id);
    if (i >= 0) dialogQueue.splice(i, 1);
    if (openDialog && openDialog.id === id) { $("dialog").hidden = true; openDialog = null; showNextDialog(); }
  }
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
    if (dialogQueue.length) {
      body.append(el("p", "sub", `${dialogQueue.length} more ${dialogQueue.length === 1 ? "question" : "questions"} from the assistant after this one.`));
    }
    const answer = async (payload) => {
      $("dialog").hidden = true;
      openDialog = null;
      try { await api("/api/dialog", Object.assign({ id: ev.id }, payload)); } catch (e) { toast(e.message, "error"); }
      showNextDialog();
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
      showNextDialog();
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
    stalled = false;
    $("stalled").hidden = true;
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
    if (ev.at) lastEventAt = ev.at;
    switch (ev.kind) {
      case "user": addUser(ev.text); break;
      case "busy":
        busy = ev.value;
        turnAt = busy ? (ev.at || serverNow()) : null;
        if (busy) stepText = "";          // a new turn is new work, even if the bar's words are the same
        updateActivity();
        if (!busy) renderNext();
        break;
      case "stall": showStalled(ev.value === true, ev.seconds); break;
      case "conversation_kept": $("kept-note").hidden = false; break;
      case "assistant_start": assistantStart(); break;
      case "assistant_delta": assistantDelta(ev.text); break;
      case "assistant_end": assistantEnd(ev); break;
      case "tool_start": toolStart(ev); break;
      case "tool_end": toolEnd(ev); break;
      case "tool_progress": setPhase(cards.get(ev.call), ev.phase, ev.at); break;
      case "search_timing": searchTiming = ev.stats || null; break;
      case "dialog": queueDialog(ev); break;
      case "dialog_closed": dropDialog(ev.id); break;
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
    clockSkew = (Number(s.now) || Date.now()) - Date.now();
    searchTiming = s.search_timing || null;
    $("layout").hidden = false;
    document.title = `Probant · ${s.matter}`;
    $("matter").textContent = String(s.matter || "").replace("/", " / ");
    if (s.date_bound) { $("bound").textContent = s.date_bound; $("bound-wrap").hidden = false; }
    renderTrust(s.trust);
    homeUrl = String(s.home || "");
    matterId = String(s.matter || "");
    if (HOME_LINK.test(homeUrl)) {
      const back = $("back");
      back.hidden = false;
      back.addEventListener("click", () => goHome(`/matter/${matterId}`));
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
  $("brand").addEventListener("click", () => goHome(""));
  $("stop").addEventListener("click", async () => {
    const b = $("stop");
    b.disabled = true;
    try {
      const r = await api("/api/abort", {});
      // `settled: false` means the assistant was told to stop and did not. Saying "Stopped." then would be
      // the same small lie as the spinner: let the stall notice appear instead, or say it plainly now.
      if (r.settled === false && !stalled) toast("It hasn't stopped yet. Give it a moment — if nothing happens, end the session.", "warning");
    } catch (e) { toast(e.message, "error"); }
    finally { b.disabled = false; }
  });
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
  $("end").addEventListener("click", () => {
    if (!window.confirm("End this session? The assistant stops; your marks and records stay with the matter.")) return;
    endSession($("end"));
  });

  init();
})();
