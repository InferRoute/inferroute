// Probant home page. Served by `ir probant home` on 127.0.0.1; talks only to it.
//
// Same rule as the session page: TEXT NODES only. The one place this page leaves itself is openLocal(), and
// it only opens addresses this computer produced: a session page on 127.0.0.1 with its key, or a record link
// from this home page. tests/test_probant_home.py pins both.
"use strict";

(() => {
  const { el, clear, markdown, renderCheck } = window.ProbantUI;
  const $ = (id) => document.getElementById(id);
  const KEY_STORE = "probant-home-key";

  // ── the key: from the URL fragment (never sent to a server), then out of the address bar ──
  let key = "";
  const frag = new URLSearchParams(location.hash.slice(1));
  if (frag.get("k")) {
    key = frag.get("k");
    try { sessionStorage.setItem(KEY_STORE, key); } catch (_) { /* keep it in memory */ }
    // `r`: open straight at a page of this home — a session page sends the professional back to its matter.
    const r = String(frag.get("r") || "");
    history.replaceState(null, "", `${location.pathname}#${/^\/[A-Za-z0-9_%./-]*$/.test(r) ? r : "/"}`);
  } else {
    try { key = sessionStorage.getItem(KEY_STORE) || ""; } catch (_) { key = ""; }
  }

  async function api(path, body) {
    const res = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: Object.assign({ authorization: `Bearer ${key}` }, body === undefined ? {} : { "content-type": "application/json" }),
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer",
    });
    let data = {};
    try { data = await res.json(); } catch (_) { data = {}; }
    if (res.status === 401) { showNoKey(); throw new Error("no key"); }
    if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
    return data;
  }

  // The only way this page opens anything: addresses this computer made for this page.
  const SESSION_LINK = /^http:\/\/127\.0\.0\.1:\d{2,5}\/#k=[A-Za-z0-9_-]{20,}$/;
  const RECORD_LINK = /^\/record\?id=[^#]*&name=[A-Za-z0-9._%-]+&v=[0-9a-f]{32}$/;
  function openLocal(url) {
    if (!SESSION_LINK.test(url) && !RECORD_LINK.test(url)) { toast("That link was not made by this computer, so it wasn't opened.", "error"); return; }
    window.open(url, "_blank", "noopener,noreferrer");
  }

  function toast(message, level) {
    const t = el("div", `toast ${level || "info"}`, String(message || ""));
    $("toasts").append(t);
    setTimeout(() => t.remove(), level === "error" ? 12000 : 6000);
  }

  const localTime = (iso) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? String(iso || "") : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short", hour12: false });
  };
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const enc = (s) => encodeURIComponent(s);
  document.getElementById("brand").addEventListener("click", () => { location.hash = "#/"; });

  function button(label, cls, onClick) {
    const b = el("button", cls || "", label);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  // ── dialogs ──
  function dialog(title, bodyNodes, actions) {
    $("dialog-title").textContent = title;
    const body = $("dialog-body");
    clear(body);
    for (const n of bodyNodes) body.append(n);
    const act = $("dialog-actions");
    clear(act);
    for (const a of actions) act.append(a);
    $("dialog").hidden = false;
  }
  const closeDialog = () => { $("dialog").hidden = true; };
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDialog(); });

  function field(label, input, hint) {
    return el("label", "field", el("span", "field-label", label), input, hint ? el("span", "field-hint", hint) : null);
  }
  function input(type, placeholder) {
    const i = document.createElement(type === "textarea" ? "textarea" : "input");
    if (type !== "textarea") i.type = type;
    if (placeholder) i.placeholder = placeholder;
    return i;
  }

  function newMatterDialog() {
    const client = input("text", "e.g. Acme");
    const matter = input("text", "e.g. cooling-system");
    const date = input("date");
    const text = input("textarea", "Describe the invention in plain technical terms. You can also add it later.");
    text.rows = 9;
    const err = el("p", "form-error");
    const create = button("Create matter", "primary", async () => {
      err.textContent = "";
      create.disabled = true;
      try {
        const r = await api("/api/matters", { client: client.value, matter: matter.value, priority_date: date.value, disclosure: text.value });
        closeDialog();
        toast(`Matter ${r.id} created.`, "info");
        location.hash = `#/matter/${enc(r.id)}`;
      } catch (e) { err.textContent = e.message; } finally { create.disabled = false; }
    });
    dialog("New matter", [
      el("p", "", "A matter is one invention you research: its folder, its date bound, its sessions and its records."),
      field("Client", client, "Letters, digits, spaces, dots, dashes."),
      field("Matter", matter),
      field("Priority date", date, "Only documents published before this date are searched. Leave empty to use today until you know it."),
      field("Disclosure", text, "Stays on this computer. Only its sealed searches leave it, encrypted."),
      err,
    ], [button("Cancel", "ghost", closeDialog), create]);
    setTimeout(() => client.focus(), 0);
  }

  async function editDisclosureDialog(matterId, onSaved) {
    let current = "";
    try { current = (await api(`/api/disclosure?id=${enc(matterId)}`)).text; } catch (e) { toast(e.message, "error"); return; }
    const text = input("textarea");
    text.rows = 16;
    text.value = current;
    const err = el("p", "form-error");
    const save = button("Save", "primary", async () => {
      try {
        const r = await api("/api/disclosure", { id: matterId, text: text.value });
        closeDialog();
        toast(`Disclosure saved (${plural(r.words, "word", "words")}).`, "info");
        onSaved();
      } catch (e) { err.textContent = e.message; }
    });
    dialog("Disclosure", [
      el("p", "", "The invention, as the assistant will read it. Saved in the matter's folder on this computer."),
      text, err,
    ], [button("Cancel", "ghost", closeDialog), save]);
  }

  // ── starting a session ──
  const watching = new Map();       // launch id → timer
  function launchBox(matterId, launch, onChange) {
    const box = el("div", "launch");
    const paint = (l) => {
      clear(box);
      if (!l) return;
      if (l.state === "starting") {
        box.className = "launch starting";
        box.append(el("div", "", el("span", "dot"), el("b", "", " Starting a session… "),
          `checking the AI machine and the search machine from this computer (${l.elapsed} s; usually under a minute).`));
      } else if (l.state === "ready") {
        box.className = "launch ready";
        box.append(el("div", "", el("b", "", "Your session is ready. "), "It opens in its own tab, checked and private."),
          button("Open the session", "primary", () => openLocal(l.url)));
      } else if (l.state === "failed") {
        box.className = "launch failed";
        box.append(el("div", "", el("b", "", "The session didn't start. "), l.message));
        // It stays until you act on it. It used to refresh the page the moment it failed, and the refreshed
        // page only knows about sessions that are starting or running — so the reason flashed for a second
        // and vanished, leaving "nothing happened" as the only feedback.
        box.append(el("div", "row actions",
          button("Try again", "primary", () => { clear(box); box.remove(); startSession(matterId, onChange); }),
          button("Dismiss", "ghost", () => { box.remove(); onChange(); })));
      } else {
        box.className = "launch";
        box.append(el("div", "", l.message || "The session has ended."));
      }
    };
    paint(launch);
    if (launch && launch.state === "starting" && !watching.has(launch.id)) {
      const timer = setInterval(async () => {
        try {
          const l = await api(`/api/launch?id=${enc(launch.id)}`);
          paint(l);
          if (l.state !== "starting") {
            clearInterval(timer);
            watching.delete(launch.id);
            if (l.state !== "failed") onChange();            // a failure stays on screen: see above
          }
        } catch (_) { /* keep trying */ }
      }, 1500);
      watching.set(launch.id, timer);
    }
    return box;
  }

  async function startSession(matterId, onChange) {
    try {
      await api("/api/sessions", { id: matterId });
      onChange();
    } catch (e) { toast(e.message, "error"); }
  }

  // ── pages ──
  const page = () => $("page");
  function stopWatching() { for (const t of watching.values()) clearInterval(t); watching.clear(); }

  async function renderMatters() {
    const p = page();
    let data;
    try { data = await api("/api/overview"); } catch (e) { return; }
    clear(p);
    p.append(el("div", "page-head", el("h1", "", "Matters"),
      el("p", "sub", "Each matter is one invention: its disclosure, its sessions with the assistant, and the records you keep.")));
    // This page is the version the server started with. When a newer one is installed, say so rather than let
    // the difference show up as a button that fails.
    if (data.update_waiting) {
      p.append(el("div", "update-note", el("b", "", "A newer version of Probant is installed. "),
        "To use it, restart Probant home: press Ctrl+C in the terminal it runs in, then run ir probant home again. "
        + "Sessions started from this page end with it, so finish them first."));
    }
    for (const l of data.running || []) {
      p.append(el("div", "running-row", el("span", "", `Session for ${l.matter}: `),
        l.state === "ready" ? button("Open the session", "primary small", () => openLocal(l.url)) : el("span", "sub", "starting…")));
    }
    if (!data.matters.length) {
      p.append(el("div", "empty-card",
        el("h2", "", "No matters yet"),
        el("p", "", "Create a matter, paste the invention's disclosure, then start a session. The assistant surveys published patents for related art, in sealed machines this computer checks first."),
        el("div", "row", button("Create your first matter", "primary", newMatterDialog), button("How it works", "ghost", () => { location.hash = "#/help"; }))));
      await renderDeleted(p);
      return;
    }
    const grid = el("div", "matters");
    for (const m of data.matters) {
      // The whole card opens the matter (Henry, 2026-09-19: "instead of open matter button we should just
      // click on the matter to open it"). Start a session is the one button, full width and primary; its
      // click must not ALSO open the matter, so it stops the event before the card sees it.
      const open = () => { location.hash = `#/matter/${enc(m.id)}`; };
      const start = button("Start a session", "primary start-session", (ev) => {
        ev.stopPropagation();
        startSession(m.id, open);
      });
      // The button sits in its own strip under a rule (Henry, 2026-09-20: "the start session button should be
      // separated somehow from the cell button"). Opening the matter is the CARD BODY's click, so the strip
      // is not part of the target either by eye or by mouse.
      const body = el("div", "matter-body",
        el("div", "matter-title", el("span", "client", m.client), el("span", "", " / "), el("b", "", m.matter)),
        el("div", "sub", `date bound ${m.date_bound || "—"}`),
        el("div", "stats",
          el("span", "", plural(m.sessions, "session", "sessions")),
          el("span", "", plural(m.searches, "search", "searches")),
          el("span", "", plural(m.marks, "mark", "marks")),
          m.disclosure_words ? el("span", "", `${m.disclosure_words} words`) : el("span", "warn-text", "no disclosure yet")),
        el("div", "sub", m.sessions ? `last session ${localTime(m.last_activity)}` : `created ${localTime(m.created_at)}`),
        el("div", "matter-open", "Open this matter →"));
      const card = el("div", "matter-card clickable", body, el("div", "matter-foot", start));
      card.tabIndex = 0;
      card.setAttribute("role", "link");
      card.setAttribute("aria-label", `Open ${m.client} / ${m.matter}`);
      body.addEventListener("click", open);
      card.addEventListener("keydown", (e) => {
        if (e.target === card && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); open(); }
      });
      grid.append(card);
    }
    p.append(grid);
    if (data.recent.length) {
      p.append(el("h2", "section", "Recent sessions"));
      p.append(sessionTable(data.recent, true));
    }
    await renderDeleted(p);
  }

  function sessionTable(sessions, withMatter) {
    const t = el("div", "sessions");
    for (const s of sessions) {
      const matterId = s.matter;
      const row = el("button", "session-row",
        el("span", "when", localTime(s.started_at)),
        withMatter ? el("span", "matter-of", matterId) : null,
        el("span", "how", s.surface === "browser" ? "browser" : s.surface === "terminal" ? "terminal" : "—"),
        el("span", "", plural(s.searches, "search", "searches")),
        el("span", "", plural(s.documents, "document", "documents")),
        el("span", s.ai_verified && s.boxed ? "ok-text" : "warn-text", s.ai_verified && s.boxed ? "✓ checked" : "◐ see details"));
      row.type = "button";
      row.addEventListener("click", () => { location.hash = `#/session/${enc(matterId)}/${enc(s.id)}`; });
      t.append(row);
    }
    return t;
  }

  async function renderMatter(matterId) {
    const p = page();
    let m;
    try { m = await api(`/api/matter?id=${enc(matterId)}`); } catch (e) { clear(p); p.append(el("p", "form-error", e.message)); return; }
    clear(p);
    const refresh = () => renderMatter(matterId);
    p.append(el("div", "crumbs", button("← Matters", "link", () => { location.hash = "#/"; })));
    const words = m.disclosure.disclosure_words;
    p.append(el("div", "page-head",
      el("h1", "", `${m.client} / ${m.matter}`),
      el("p", "sub", `Date bound ${m.date_bound}${m.pre_filing_default ? " (today's date, until you set the real priority date)" : ""} · created ${localTime(m.created_at)}`)));
    p.append(el("div", "row actions",
      button("Start a session", "primary", () => startSession(m.id, refresh)),
      button(words ? "Edit disclosure" : "Write the disclosure", "ghost", () => editDisclosureDialog(m.id, refresh)),
      button("Export the record", "ghost", async (ev) => {
        const b = ev.currentTarget;
        b.disabled = true;
        try {
          const r = await api("/api/export", { id: m.id });
          toast("Record exported.", "info");
          await renderMatter(matterId);
          openLocal(r.view);
        } catch (e) { toast(e.message, "error"); } finally { b.disabled = false; }
      })));
    if (!words) p.append(el("p", "warn-text", "This matter has no disclosure yet. Write it before starting a session, so the assistant has something to survey."));
    if (m.running) p.append(launchBox(m.id, m.running, refresh));

    p.append(el("h2", "section", "Sessions"));
    if (!m.sessions.length) p.append(el("p", "sub", "No sessions yet. Start one: the assistant reads the disclosure and surveys published patents with you."));
    else p.append(sessionTable(m.sessions.map((s) => ({ ...s, matter: m.id })), false));

    const markEntries = Object.entries(m.marks || {});
    p.append(el("h2", "section", "Your marks"));
    if (!markEntries.length) p.append(el("p", "sub", "No marks yet. Mark documents in a session as relevant, not relevant, or known."));
    else {
      const counts = { relevant: 0, "not-relevant": 0, known: 0 };
      for (const [, v] of markEntries) counts[v] = (counts[v] || 0) + 1;
      p.append(el("p", "", `${counts.relevant} relevant · ${counts["not-relevant"]} not relevant · ${counts.known} known`));
      p.append(el("div", "mark-list", ...markEntries.map(([k, v]) => el("span", `mark-chip m-${v}`, `${k} · ${v.replace("-", " ")}`))));
    }

    p.append(el("h2", "section", "Records"));
    if (!m.exports.length) p.append(el("p", "sub", "No exported records yet. Export one to keep, share or check the matter's research."));
    else {
      const list = el("div", "sessions");
      for (const e of m.exports) {
        const result = el("div", "check-result");
        result.hidden = true;
        list.append(el("div", "record-row", el("span", "when", `Exported ${localTime(e.made_at)}`),
          el("span", "mono sub", e.folder), button("Open record", "ghost small", () => openLocal(e.view)),
          button("Check this record", "ghost small", (ev) => runCheck(m.id, e.name, ev.currentTarget, result))),
          result);
      }
      p.append(list);
    }
    p.append(el("p", "sub folder-line", `Matter folder: ${m.disclosure.folder}`));
    p.append(el("div", "danger-zone",
      el("div", "", el("b", "", "Delete this matter"),
        el("p", "sub", "Its disclosure, sessions, marks and exported records go to Recently deleted. You can restore "
          + "it from there for 30 days; after that it is erased from this computer.")),
      button("Delete matter", "danger small", () => deleteMatterDialog(m))));
  }

  // Deleting asks for the matter's name to be TYPED: a matter holds signed search records that cannot be made
  // again, and one click on the wrong button must not be enough to lose them.
  function deleteMatterDialog(m) {
    const typed = input("text", m.matter);
    const err = el("p", "form-error");
    const go = button("Delete matter", "danger", async () => {
      err.textContent = "";
      go.disabled = true;
      try {
        const r = await api("/api/matter/delete", { id: m.id, confirm: typed.value });
        closeDialog();
        toast(`${m.client} / ${m.matter} deleted. Restore it from Recently deleted within ${r.days} days.`, "info");
        for (const left of r.left_in_place || []) toast(`Left in place, outside the Probant folder: ${left}`, "info");
        location.hash = "#/";
      } catch (e) { err.textContent = e.message; } finally { go.disabled = false; }
    });
    go.disabled = true;
    typed.addEventListener("input", () => { go.disabled = typed.value.trim() !== m.matter; });
    dialog(`Delete ${m.client} / ${m.matter}?`, [
      el("p", "", "This moves the matter's disclosure, sessions, marks and exported records out of Probant. "
        + "They stay in Recently deleted for 30 days, where you can restore them, then they are erased."),
      field("Type the matter's name to confirm", typed),
      err,
    ], [button("Cancel", "ghost", closeDialog), go]);
    setTimeout(() => typed.focus(), 0);
  }

  async function renderDeleted(p) {
    let d;
    try { d = await api("/api/deleted"); } catch (e) { return; }
    if (!d.deleted.length) return;
    const list = el("div", "sessions deleted-list");
    for (const x of d.deleted) {
      const row = el("div", "record-row",
        el("span", "", x.matter),
        el("span", "sub", `deleted ${localTime(x.deleted_at)} · erased ${localTime(x.erase_after)}`),
        button("Restore", "ghost small", async (ev) => {
          const b = ev.currentTarget;                 // currentTarget is null again once this awaits
          b.disabled = true;
          try { const r = await api("/api/deleted/restore", { id: x.id }); toast(`${r.id} restored.`, "info"); renderMatters(); }
          catch (e) { toast(e.message, "error"); b.disabled = false; }
        }),
        button("Erase now", "danger small", async (ev) => {
          if (!window.confirm(`Erase ${x.matter} for good? This cannot be undone.`)) return;
          try { await api("/api/deleted/erase", { id: x.id }); toast(`${x.matter} erased.`, "info"); renderMatters(); }
          catch (e) { toast(e.message, "error"); }
        }));
      list.append(row);
    }
    p.append(el("h2", "section", "Recently deleted"),
      el("p", "sub", `Kept for ${d.days} days after deletion, then erased from this computer.`), list);
  }

  // ── checking an exported record, here, without a terminal (the words are common.js renderCheck) ──
  async function runCheck(matterId, name, btn, box) {
    btn.disabled = true;
    btn.textContent = "Checking…";
    clear(box);
    box.hidden = false;
    box.append(el("p", "sub", "Running the record's own verifier. This takes a few seconds."));
    let r;
    try { r = await api("/api/check", { id: matterId, name }); }
    catch (e) { clear(box); box.append(el("p", "form-error", `The check could not be run: ${e.message}`)); return; }
    finally { btn.disabled = false; btn.textContent = "Check this record"; }
    renderCheck(box, r);
  }

  async function renderSession(matterId, sid) {
    const p = page();
    let s;
    try { s = await api(`/api/session?id=${enc(matterId)}&sid=${enc(sid)}`); } catch (e) { clear(p); p.append(el("p", "form-error", e.message)); return; }
    clear(p);
    p.append(el("div", "crumbs", button("← Matters", "link", () => { location.hash = "#/"; }), el("span", "sub", " / "),
      button(matterId, "link", () => { location.hash = `#/matter/${enc(matterId)}`; })));
    p.append(el("div", "page-head", el("h1", "", `Session of ${localTime(s.started_at)}`),
      el("p", "sub", `${s.surface === "browser" ? "In the browser" : s.surface === "terminal" ? "In the terminal" : "Screen not recorded"} · ${plural(s.searches.length, "search", "searches")} · ${plural(s.documents || 0, "document", "documents")}`)));
    p.append(el("div", "checks",
      el("div", s.model.verified ? "ok-text" : "bad-text", s.model.verified ? `✓ The AI ran in a sealed machine this computer verified (${s.model.checks || "checks passed"})` : "✗ The AI machine was not verified in this session"),
      el("div", s.boxed ? "ok-text" : "warn-text", s.boxed ? "✓ The assistant worked in a closed box: no internet, only the matter's folder" : "◐ The assistant was not fully boxed in this session"),
      s.unanswered ? el("div", "warn-text", `◐ ${plural(s.unanswered, "search was", "searches were")} sent but never answered`) : null));

    p.append(el("h2", "section", "Conversation"));
    if (!s.conversation) {
      p.append(el("p", "sub", s.surface === "browser"
        ? "This session's conversation wasn't kept (it ran before conversations were kept)."
        : "Conversations aren't kept for terminal sessions. The searches below are."));
    } else {
      const conv = el("div", "conversation");
      for (const row of s.conversation) {
        if (row.kind === "user") conv.append(el("div", "msg msg-user", row.text));
        else if (row.kind === "assistant") { const n = el("div", "msg msg-assistant"); n.append(markdown(row.text)); conv.append(n); }
        else if (row.kind === "search") {
          const what = row.feature ? ` · ${row.feature}` : row.like ? ` · documents like ${row.like}` : "";
          conv.append(el("div", "step", el("span", "step-dot", "·"), el("span", "",
            row.ok ? `Sealed search${row.search_no ? ` ${row.search_no}` : ""}${what}: ${plural(row.documents, "document", "documents")}` : "A search was not sent")));
        } else if (row.kind === "marks_read") conv.append(el("div", "step", el("span", "step-dot", "·"), el("span", "", "Read your relevance marks")));
        else if (row.kind === "approval") conv.append(el("div", "step", el("span", "step-dot", "·"), el("span", "", row.answer === "allowed" ? "You allowed searches to the search machine" : "You declined a search")));
      }
      conv.append(el("p", "sub", "Kept with the matter on this computer, readable only by your account."));
      p.append(conv);
    }

    p.append(el("h2", "section", "Searches"));
    if (!s.searches.length) p.append(el("p", "sub", "No sealed search completed in this session."));
    for (const x of s.searches) {
      const card = el("div", "card");
      card.append(el("div", "card-head", el("span", "title", `🔍 Search ${x.n}`), el("span", "sub", `${localTime(x.at)} · ${plural(x.documents.length, "document", "documents")}`)));
      if (x.query) card.append(el("div", "card-query", x.query.length > 400 ? `${x.query.slice(0, 400)}…` : x.query));
      const list = el("ol", "docs");
      x.documents.forEach((d, i) => {
        const mark = s.marks[d.key];
        list.append(el("li", "doc",
          el("span", "rank", String(i + 1)),
          el("div", "", el("span", "key", d.key), d.year ? el("span", "year", String(d.year)) : null, el("div", "dtitle", d.title)),
          mark ? el("span", `mark-chip m-${mark}`, mark.replace("-", " ")) : el("span", "")));
      });
      card.append(list);
      p.append(card);
    }
  }

  function renderHelp() {
    const p = page();
    clear(p);
    const sec = (title, ...nodes) => el("section", "help-section", el("h2", "", title), ...nodes);
    const para = (t) => el("p", "", t);
    const list = (...items) => el("ul", "", ...items.map((t) => el("li", "", t)));
    p.append(el("div", "page-head", el("h1", "", "How Probant works"),
      el("p", "sub", "A private assistant for prior-art research: it surveys published patents with you, and every search leaves a record anyone can check.")));
    p.append(
      sec("1. Create a matter",
        para("A matter is one invention. Give it a client and a name, the priority date, and the disclosure: the invention described in plain technical terms."),
        list("The priority date is the matter's date bound: only documents published before it are searched. The assistant can't change it.",
          "The disclosure stays on this computer, in the matter's folder. You can edit it any time.")),
      sec("2. Start a session",
        para("Start a session from the matter. Before anything is sent, this computer checks two sealed machines: the one the AI runs in, and the one the patent search runs in. A sealed machine encrypts its own memory with a key held by its chip, so even the people who run it can't look inside."),
        list("The session opens in its own tab. The panel on the right says what protects the matter, in plain words, with the technical detail one click away.",
          "A green Private means both machines checked out and the assistant works in a closed box: no internet, and no files beyond the matter's folder.")),
      sec("3. Research with the assistant",
        list("Ask for a prior-art survey of the disclosure, or anything more specific.",
          "Before its first search, the assistant shows you the exact text it wants to send. Nothing is searched until you allow it.",
          "Ask for a search on one feature on its own, for documents like one it found, or for more results (quick 10, standard 25, broad 50).",
          "After each answer, next-step buttons suggest where to go. Each sends exactly the words it shows.")),
      sec("4. Mark what matters",
        list("Mark returned documents as relevant, not relevant, or known. Marks save as you click.",
          "The assistant reads your marks to steer its next searches, and the steps under “From your marks” update as you mark. It can't make or change a mark: they are your judgement.",
          "“Look deeper at the ones I marked relevant” researches around what you marked.")),
      sec("5. Keep the record",
        list("Export the record from the matter or the session. It opens with “At a glance”: what it holds, and who stands behind each line.",
          "Each search in it is signed by the search machine, with the hardware report that identifies it. Anyone can check it without trusting InferRoute: in the record's folder, run python3 verify_record.py with InferRoute's reference file and the key from your engagement letter.",
          "The record holds the disclosure in plain text: store it like the client file.")),
      sec("What stays private",
        list("Your disclosure and conversation are read only on this computer and inside the two sealed machines.",
          "The services in between see when you work and how much you send, never the words.",
          "Browser conversations are kept with the matter on this computer, readable only by your account. Terminal sessions keep their searches, not the conversation.")),
      sec("What it can't prove",
        list("The chips prove where your text can be read, not what the software there does with it. The search machine runs InferRoute's own published software; the AI machine runs its operator's published software, which InferRoute re-checks in part.",
          "A search finds related documents. It doesn't prove novelty, or that nothing else exists.",
          "Browser extensions allowed to read every page can read these pages too. For client matters, use a browser profile without extensions.")),
      sec("Limits right now",
        list("The assistant reads each document's title and the start of its abstract, not the full text.",
          "There are no filters yet for classification, country or applicant.",
          "Record checks currently show one known failure, completeness, until the next update of the search machine.")),
      sec("In the terminal",
        para("Everything here also works in a terminal:"),
        list("ir probant new <client> <matter> --priority-date YYYY-MM-DD",
          "ir probant open <client>/<matter>   (add --web for the browser)",
          "In a session: /relevant <number>, /not-relevant, /known, /marks, /next <n>, /proof, /quit",
          "ir probant export <client>/<matter>, and ir probant proof <client>/<matter> for the technical detail")));
  }

  // ── reading a document: the professional gives it, a sealed session reads it, they open what it proposes ──
  //
  // The file is read HERE, by the browser, and posted as text: the page is served by this computer, so the
  // document never leaves it either way — but reading it locally means no upload of a file we then have to
  // say we deleted.
  function readDocumentDialog() {
    const file = input("file");
    file.accept = ".txt,.md,.text,text/plain,text/markdown";
    const text = input("textarea", "…or paste the document here.");
    text.rows = 8;
    const err = el("p", "form-error");
    const chosen = el("p", "sub");
    let picked = "";
    file.addEventListener("change", async () => {
      const f = file.files && file.files[0];
      if (!f) return;
      picked = f.name;
      try {
        text.value = await f.text();
        chosen.textContent = `${f.name} · ${text.value.length.toLocaleString()} characters`;
      } catch (e) { err.textContent = `That file could not be read here: ${e.message}`; }
    });
    const go = button("Read it", "primary", async () => {
      err.textContent = "";
      const body = text.value.trim();
      if (!body) { err.textContent = "Choose a text file, or paste the document."; return; }
      go.disabled = true;
      go.textContent = "Staging…";
      try {
        const r = await api("/api/intake", { text: text.value, name: picked || "pasted document" });
        closeDialog();
        location.hash = `#/document/${enc(r.id)}`;
      } catch (e) { err.textContent = e.message; go.disabled = false; go.textContent = "Read it"; }
    });
    dialog("Read a document", [
      el("p", "", "A sealed session reads the whole document and proposes the inventions it finds as matters "
        + "you can open. It has no search tool while it reads, so nothing about the document goes to a search machine."),
      field("Document", file, "A text file (.txt or .md). It is read on this computer and never uploaded anywhere."),
      chosen,
      field("Or paste it", text),
      err,
    ], [button("Cancel", "ghost", closeDialog), go]);
  }

  // Proposals arrive WHILE the session reads, so this view refreshes itself until the reading ends. Keyed in
  // the same map the launch poller uses, so leaving the page stops it (route() clears them all).
  function watchDocument(id) {
    const key = `doc:${id}`;
    if (watching.has(key)) return;
    watching.set(key, setInterval(() => {
      if (location.hash.startsWith(`#/document/${enc(id)}`)) renderDocument(id);
      else { clearInterval(watching.get(key)); watching.delete(key); }
    }, 4000));
  }

  async function renderDocument(id) {
    const p = page();
    let d;
    try { d = await api(`/api/intake?id=${enc(id)}`); } catch (e) { clear(p); p.append(el("p", "form-error", e.message)); return; }
    clear(p);
    p.append(el("div", "crumbs", button("← Matters", "link", () => { location.hash = "#/"; })));
    p.append(el("div", "page-head", el("h1", "", d.meta.source_name),
      el("p", "sub", `${d.meta.chars.toLocaleString()} characters · staged ${localTime(d.meta.staged_at)}`)));
    if (d.running) {
      p.append(launchBox(`document · ${d.meta.source_name}`, d.running, () => renderDocument(id)));
      p.append(el("p", "sub", "It proposes matters as it reads; they appear here. A long document takes a few minutes."));
      watchDocument(id);
    }
    p.append(el("h2", "section", "Proposed matters"));
    if (!d.proposals.length) {
      p.append(el("p", "sub", d.running ? "Nothing proposed yet." : "This reading proposed no matters."));
    }
    for (const [i, pr] of d.proposals.entries()) {
      const card = el("div", "card proposal",
        el("div", "card-head", el("span", "title", pr.title),
          pr.priority_date ? el("span", "sub", `priority date ${pr.priority_date}`) : el("span", "sub", "")),
        el("div", "card-body", el("p", "", pr.summary),
          el("blockquote", "quote", pr.quote),
          el("p", "sub", "The passage above is quoted from the document; a proposal whose quote is not in the "
            + "document is discarded before it reaches this page.")),
        el("div", "card-actions", button("Open this as a matter", "primary small", () => openProposalDialog(id, i, pr))));
      p.append(card);
    }
    if (d.dropped) {
      p.append(el("p", "sub", `${plural(d.dropped, "proposal was", "proposals were")} discarded: the quote was not in the document.`));
    }
  }

  function openProposalDialog(id, index, proposal) {
    const client = input("text", "e.g. Acme");
    const matter = input("text", proposal.suggested_matter);
    matter.value = proposal.suggested_matter;
    const date = input("date");
    if (proposal.priority_date) date.value = proposal.priority_date;
    const err = el("p", "form-error");
    const go = button("Open the matter", "primary", async () => {
      err.textContent = "";
      go.disabled = true;
      try {
        const r = await api("/api/intake/create", { id, index, client: client.value, matter: matter.value,
                                                    priority_date: date.value });
        closeDialog();
        toast(`Matter ${r.id} opened.`, "info");
        location.hash = `#/matter/${enc(r.id)}`;
      } catch (e) { err.textContent = e.message; go.disabled = false; }
    });
    dialog(`Open "${proposal.title}" as a matter`, [
      el("p", "", "The proposal becomes the matter's disclosure, with the passage it came from and the document it was read from."),
      field("Client", client),
      field("Matter", matter, "You name it; the suggestion comes from the title."),
      field("Priority date", date, "Only documents published before this date are searched. Empty means today, until you know it."),
      err,
    ], [button("Cancel", "ghost", closeDialog), go]);
    setTimeout(() => client.focus(), 0);
  }

  // ── sharing a corpus of matters with another Probant user ──
  //
  // Nothing secret is ever shown or sent: what leaves this page is a card of PUBLIC keys, and what the
  // other person receives is sealed to their key alone. The one thing a person must do off-screen is read
  // a fingerprint aloud — so the page says that where they will read it, not in a help page.
  async function renderSharing() {
    const p = page();
    let d;
    try { d = await api("/api/sharing"); } catch (e) { clear(p); p.append(el("p", "form-error", e.message)); return; }
    clear(p);
    p.append(el("div", "page-head", el("h1", "", "Sharing"),
      el("p", "sub", "Send a corpus of matters to another Probant user — your lawyer, your co-counsel. "
        + "They open it as matters of their own and run their own searches, on their own account.")));

    p.append(el("h2", "section", "You"));
    p.append(el("div", "fingerprint-card",
      el("div", "sub", "Your fingerprint — read it to them, and check theirs the same way."),
      el("div", "fingerprint", d.fingerprint),
      el("p", "sub", "Send them your card below. It holds public keys only: anyone who reads it learns "
        + "nothing and can decrypt nothing."),
      el("textarea", "card-box", JSON.stringify(d.card, null, 1)),
      button("Copy your card", "ghost small", () => navigator.clipboard
        .writeText(JSON.stringify(d.card, null, 1)).then(() => toast("Copied.", "info")).catch(() => {}))));

    // Deliveries — what has actually gone out and come in. Without this the page can seal a corpus and
    // open one while showing no sign that either happened.
    p.append(el("h2", "section", "Deliveries"));
    if (!(d.corpora || []).length) {
      p.append(el("p", "sub", "Nothing sent or received yet. A delivery is matters sealed together with "
        + "the documents that describe them; it keeps its own identity on both sides."));
    }
    for (const c of d.corpora || []) {
      const sent = c.direction === "sent";
      const who = sent ? `sent to ${c.to || "?"}` : `from ${c.from_name || c.from || "unknown sender"}`;
      const warn = (!sent && !c.known_contact)
        ? el("span", "warn", "sender not a known contact") : el("span", "");
      p.append(el("div", "record-row",
        el("span", "", c.name || "(unnamed)"),
        el("span", "mono sub", c.id),
        el("span", "sub", `${sent ? "sent" : "received"} · ${who}`),
        warn));
      if ((c.files || []).length) {
        p.append(el("p", "sub", `documents: ${c.files.join(", ")}`));
      }
      if ((c.matters || []).length) {
        p.append(el("p", "sub", `matters: ${c.matters.join(", ")}`));
      }
    }

    p.append(el("h2", "section", "People you can share with"));
    if (!d.contacts.length) p.append(el("p", "sub", "Nobody yet. Add someone with the card they sent you."));
    for (const c of d.contacts) {
      p.append(el("div", "record-row", el("span", "", c.name), el("span", "mono sub", c.fingerprint),
        el("span", "sub", `added ${localTime(c.added_at)}`), el("span", "")));
    }
    p.append(el("div", "row", button("Add someone", "ghost", () => addContactDialog(() => renderSharing())),
      button("Open a share sent to you", "ghost", () => openShareDialog())));

    p.append(el("h2", "section", "Send matters"));
    if (!d.contacts.length) {
      p.append(el("p", "sub", "Add someone first: you seal a corpus to their key, so you need their card."));
      return;
    }
    let matters = [];
    try { matters = (await api("/api/overview")).matters; } catch (_) { matters = []; }
    if (!matters.length) { p.append(el("p", "sub", "No matters to send yet.")); return; }
    const chosen = new Set();
    const list = el("div", "sessions");
    for (const m of matters) {
      const box = input("checkbox");
      box.addEventListener("change", () => { box.checked ? chosen.add(m.id) : chosen.delete(m.id); });
      list.append(el("label", "record-row pick", box, el("span", "", m.id),
        el("span", "sub", `date bound ${m.date_bound || "—"}`),
        el("span", "sub", plural(m.marks, "mark", "marks"))));
    }
    // Documents that describe the WHOLE corpus — a matter list, a reading guide. They quote every filing,
    // so they travel inside the seal with the matters rather than as attachments to an email.
    const docs = new Set();
    const docBox = el("div", "sessions");
    for (const f of d.documents || []) {
      const box = input("checkbox");
      box.addEventListener("change", () => { box.checked ? docs.add(f.id) : docs.delete(f.id); });
      docBox.append(el("label", "record-row pick", box, el("span", "", f.name),
        el("span", "sub", f.run), el("span", "sub", `${Math.round((f.bytes || 0) / 1000)} KB`)));
    }
    const to = document.createElement("select");
    for (const c of d.contacts) {
      const o = document.createElement("option");
      o.value = c.name;
      o.textContent = `${c.name} · ${c.fingerprint}`;
      to.append(o);
    }
    const note = input("textarea", "A line for them: what this is, and what you want back.");
    note.rows = 2;
    const result = el("div", "share-result");
    result.hidden = true;
    const go = button("Seal and write the file", "primary", async () => {
      if (!chosen.size) { toast("Choose at least one matter.", "error"); return; }
      go.disabled = true;
      try {
        const r = await api("/api/sharing/share", { to: to.value, matters: [...chosen], note: note.value,
                                                    documents: [...docs], corpus_name: corpusName.value });
        clear(result);
        result.hidden = false;
        result.append(el("div", "", el("b", "", `${r.matters} matter(s)`
          + (r.documents && r.documents.length ? ` and ${r.documents.length} document(s)` : "")
          + ` sealed to ${to.value}`),
          ` (${r.to_fingerprint}), signed as ${r.from_fingerprint}.`),
          el("span", "mono", r.path),
          el("p", "sub", "Send that file however you like — email, a share, a USB stick. Only their "
            + "fingerprint can open it, and a copy is sealed to you so you can reopen what you sent."),
          button("Copy the path", "ghost small", () => navigator.clipboard.writeText(r.path)
            .then(() => toast("Copied.", "info")).catch(() => {})));
      } catch (e) { toast(e.message, "error"); } finally { go.disabled = false; }
    });
    const corpusName = input("text", "e.g. InferRoute portfolio — 9 filings + surplus");
    p.append(list);
    if ((d.documents || []).length) {
      p.append(el("h2", "section", "Documents about the whole corpus"),
        el("p", "sub", "These describe the portfolio rather than any one matter — a matter list, a reading "
          + "guide. They quote the filings, so they are sealed with the matters, never attached to an email."),
        docBox);
    }
    p.append(field("Send to", to), field("Name this corpus", corpusName), field("A note for them", note),
             el("div", "row", go), result);
  }

  function addContactDialog(onAdded) {
    const name = input("text", "e.g. betrancourt");
    const card = input("textarea", "Paste the card they sent you.");
    card.rows = 6;
    const err = el("p", "form-error");
    const go = button("Add", "primary", async () => {
      err.textContent = "";
      try {
        const r = await api("/api/sharing/contact", { name: name.value, card: card.value });
        closeDialog();
        toast(`${r.name} added — fingerprint ${r.fingerprint}`, "info");
        onAdded();
      } catch (e) { err.textContent = e.message; }
    });
    dialog("Add someone to share with", [
      el("p", "", "Paste the card they sent you. Probant works out the fingerprint from the keys in it — "
        + "then CONFIRM that fingerprint with them by voice before you send anything. A card that reached "
        + "you the same way an impostor's would is worth what that channel is worth."),
      field("Name", name, "What you will call them here."),
      field("Their card", card),
      err,
    ], [button("Cancel", "ghost", closeDialog), go]);
  }

  function openShareDialog() {
    const path = input("text", "/home/you/probant-corpus-for-you-….probant-share");
    const client = input("text", "e.g. Henry");
    const err = el("p", "form-error");
    const preview = el("div", "share-result");
    preview.hidden = true;
    const look = button("Look at it", "ghost", async () => {
      err.textContent = "";
      try {
        const r = await api("/api/sharing/open", { path: path.value });
        clear(preview);
        preview.hidden = false;
        preview.append(el("div", "", el("b", "", `Signed by ${r.from_name || "an UNKNOWN sender"}`),
          ` — fingerprint ${r.from}`));
        if (!r.known) {
          preview.append(el("p", "warn-text", "This fingerprint is not one of your contacts. The signature "
            + "proves the matters are as that key wrote them; it does not say whose key it is. Confirm it "
            + "by voice before you rely on this."));
        }
        if (r.note) preview.append(el("p", "", r.note));
        if (r.corpus) preview.append(el("p", "sub", `Corpus: ${r.corpus}`));
        for (const f of r.documents || []) {
          preview.append(el("div", "record-row", el("span", "", f.name),
            el("span", "sub", "describes the whole corpus"),
            el("span", "sub", `${Math.round((f.bytes || 0) / 1000)} KB`), el("span", "")));
        }
        for (const m of r.matters) {
          preview.append(el("div", "record-row", el("span", "", m.matter),
            el("span", "sub", `date bound ${m.date_bound || "—"}`),
            el("span", "sub", `${m.claims} claim(s)`), el("span", "sub", `${m.marks} mark(s) of theirs`)));
        }
      } catch (e) { err.textContent = e.message; }
    });
    const go = button("Open them as my matters", "primary", async () => {
      err.textContent = "";
      go.disabled = true;
      try {
        const r = await api("/api/sharing/open", { path: path.value, client: client.value });
        closeDialog();
        const extra = (r.documents || []).length ? ` and ${r.documents.length} document(s) in ${r.corpus_dir}` : "";
        toast(`Opened ${r.opened.length} matter(s)${extra}.`, "info");
        location.hash = "#/";
      } catch (e) { err.textContent = e.message; go.disabled = false; }
    });
    dialog("Open a share sent to you", [
      el("p", "", "A file someone sealed to your fingerprint. Look at it first: who signed it, and what is "
        + "inside. Opening it creates one matter of your own per matter in the share, each with the date "
        + "bound the sender set."),
      field("The file", path),
      field("Open them under this client name", client, "Yours to choose — e.g. the sender's name."),
      err, preview,
    ], [button("Cancel", "ghost", closeDialog), look, go]);
  }

  // ── routing ──
  async function route() {
    stopWatching();
    closeDialog();
    const h = location.hash || "#/";
    const parts = h.replace(/^#\/?/, "").split("/").map((x) => decodeURIComponent(x));
    const here = parts[0] === "help" ? "#/help" : parts[0] === "sharing" ? "#/sharing" : "#/";
    for (const b of document.querySelectorAll("#nav button")) b.classList.toggle("active", b.dataset.route === here);
    // A matter id ("client/matter") travels encoded as ONE segment: #/matter/Acme%2Fcooling.
    if (parts[0] === "matter" && parts[1]) return renderMatter(parts[1]);
    if (parts[0] === "session" && parts[1] && parts[2]) return renderSession(parts[1], parts[2]);
    if (parts[0] === "document" && parts[1]) return renderDocument(parts[1]);
    if (parts[0] === "sharing") return renderSharing();
    if (parts[0] === "help") return renderHelp();
    return renderMatters();
  }

  function showNoKey() {
    $("nokey").hidden = false;
    $("page").hidden = true;
    $("nav").hidden = true;
    $("new-matter").hidden = true;
    $("read-document").hidden = true;
  }

  if (!key) { showNoKey(); return; }
  $("page").hidden = false;
  $("nav").hidden = false;
  $("new-matter").hidden = false;
  $("new-matter").addEventListener("click", newMatterDialog);
  $("read-document").hidden = false;
  $("read-document").addEventListener("click", readDocumentDialog);
  for (const b of document.querySelectorAll("#nav button")) b.addEventListener("click", () => { location.hash = b.dataset.route; });
  window.addEventListener("hashchange", route);
  route();
})();
