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
    let res;
    try { res = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: Object.assign({ authorization: `Bearer ${key}` }, body === undefined ? {} : { "content-type": "application/json" }),
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer",
    }); } catch (_) {
      throw new Error("Could not reach Probant. Check that its Terminal is still running, then try again.");
    }
    let data = {};
    try { data = await res.json(); } catch (_) { data = {}; }
    if (res.status === 401) { showNoKey(); throw new Error("no key"); }
    if (!res.ok) {
      const error = new Error(data.error || (res.status >= 500
        ? "Probant could not finish this action. Try again; if it repeats, check the Terminal for details."
        : "This action could not be completed. Refresh the page and try again."));
      error.fields = data.fields || {};
      throw error;
    }
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

  // A yes/no on the page's own dialog. Ending a session stops work in progress, so it is never a bare
  // click — but it must still be reachable, which is the whole point of putting it here.
  function confirmBox(title, text, confirmLabel = "End the session") {
    return new Promise((resolve) => {
      dialog(title, [el("p", "", text)], [
        button("Cancel", "ghost", () => { closeDialog(); resolve(false); }),
        button(confirmLabel, "primary", () => { closeDialog(); resolve(true); }),
      ]);
    });
  }
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

  let formFieldId = 0;
  function formErrors(inputs) {
    const messages = {};
    for (const [name, control] of Object.entries(inputs)) {
      const message = el("span", "form-error");
      message.id = `form-error-${++formFieldId}`;
      message.hidden = true;
      control.setAttribute("aria-describedby", message.id);
      message.setAttribute("aria-live", "polite");
      messages[name] = message;
      control.addEventListener("input", () => {
        message.hidden = true;
        message.textContent = "";
        control.removeAttribute("aria-invalid");
      });
    }
    function show(errors) {
      let first;
      for (const [name, control] of Object.entries(inputs)) {
        const text = errors[name] || "";
        messages[name].textContent = text;
        messages[name].hidden = !text;
        if (text) { control.setAttribute("aria-invalid", "true"); first ||= control; }
        else control.removeAttribute("aria-invalid");
      }
      if (first) first.focus();
      return !first;
    }
    function validate() {
      const errors = {};
      for (const name of ["client", "matter"]) {
        const value = inputs[name].value.trim();
        if (!value) errors[name] = `Enter a ${name} name, for example ${name === "client" ? "Personal" : "bread-and-butter"}.`;
        else if (value.length > 64) errors[name] = `Use a shorter ${name} name (64 characters or fewer).`;
        else if (!/^[A-Za-z0-9][A-Za-z0-9 _.-]*$/.test(value)) errors[name] = "Start with a letter or number. Use letters, numbers, spaces, dots, dashes or underscores.";
      }
      if (inputs.priority_date.validity && !inputs.priority_date.validity.valid) {
        errors.priority_date = "Choose a valid priority date, or leave it blank to use today.";
      }
      if (inputs.disclosure && inputs.disclosure.value.length > 200000) {
        errors.disclosure = "Keep the disclosure under 200,000 characters. Use Read document for a longer text.";
      }
      return show(errors);
    }
    return { show, validate, field: (name, label, hint) => {
      const node = field(label, inputs[name], hint);
      node.append(messages[name]);
      return node;
    } };
  }

  function newMatterDialog() {
    const client = input("text", "e.g. Acme");
    const matter = input("text", "e.g. cooling-system");
    const date = input("date");
    const text = input("textarea", "Describe the invention in plain technical terms. You can also add it later.");
    text.rows = 9;
    const validation = formErrors({ client, matter, priority_date: date, disclosure: text });
    const err = el("p", "form-error");
    const create = button("Create matter", "primary", async () => {
      err.textContent = "";
      if (!validation.validate()) return;
      create.disabled = true;
      try {
        const r = await api("/api/matters", { client: client.value, matter: matter.value, priority_date: date.value, disclosure: text.value });
        closeDialog();
        toast(`Matter ${r.id} created.`, "info");
        location.hash = `#/matter/${enc(r.id)}`;
      } catch (e) {
        if (Object.keys(e.fields || {}).length) validation.show(e.fields);
        else err.textContent = `Could not create the matter. ${e.message}`;
      } finally { create.disabled = false; }
    });
    dialog("New matter", [
      el("p", "", "A matter is one invention you research: its folder, its date bound, its sessions and its records."),
      validation.field("client", "Client", "Required. Use Personal if this is for yourself."),
      validation.field("matter", "Matter", "Required. A short name for this invention."),
      validation.field("priority_date", "Priority date", "Only documents published before this date are searched. Leave empty to use today until you know it."),
      validation.field("disclosure", "Disclosure", "Saved as written. The AI reads it when you start a session."),
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

  async function reviewDraftDialog(m, onSaved) {
    const text = input("textarea");
    text.rows = 16;
    const date = input("date");
    const origin = m.intake_origin || {};
    date.value = origin.suggested_priority_date || (m.pre_filing_default ? "" : m.date_bound);
    try { text.value = (await api(`/api/disclosure?id=${enc(m.id)}`)).text; }
    catch (e) { toast(e.message, "error"); return; }
    const err = el("p", "form-error");
    const save = button("Save reviewed draft", "primary", async () => {
      err.textContent = "";
      if (!text.value.trim()) { err.textContent = "Enter the disclosure before saving your review."; text.focus(); return; }
      if (!date.validity.valid) { err.textContent = "Choose a valid priority date or leave it blank to use today."; date.focus(); return; }
      save.disabled = true;
      try {
        await api("/api/intake/review", { id: m.id, text: text.value, priority_date: date.value });
        closeDialog(); toast("Draft reviewed. You can now start a session."); onSaved();
      } catch (e) { err.textContent = e.message; save.disabled = false; }
    });
    dialog("Review draft matter", [
      el("p", "", "Check the AI's description against its supporting passage. Correct missing or overstated features before searching."),
      el("p", "sub", `Source: ${origin.source_name || "uploaded document"}`),
      field("Disclosure", text),
      field("Priority date", date, origin.suggested_priority_date
        ? "Suggested by the AI from the source. Confirm it; leave blank to use today."
        : "No priority date was supplied. Leave blank to use today, or enter the date you have confirmed."),
      err,
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
          el("div", "row actions",
            button("Open the session", "primary", () => openLocal(l.url)),
            // END IT FROM HERE. Without this a session could only be ended from inside its own tab, so one
            // whose page is unreachable — closed, crashed, or a 127.0.0.1 link opened from another machine
            // — left its matter permanently undeletable with no remedy the reader could reach.
            button("End this session", "ghost", async () => {
              if (!(await confirmBox("End this session?",
                    "The session stops and its page closes. Searches and marks already recorded are kept."))) return;
              try {
                await api("/api/sessions/end", { id: matterId });
                toast("Session ended.", "info");
                if (onChange) onChange();
              } catch (e) { toast(`Could not end it: ${e.message}`, "error"); }
            })));
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

  // ── is the search machine up, and when is it meant to be ──
  //
  // The sealed search machine is scheduled, not permanent, so "not answering" is usually the timetable
  // rather than a fault — and saying "unavailable" flatly would read as breakage twenty-two hours a day.
  // The window comes from the server as instants: the hours are named in Paris time, and anyone reading
  // this from another timezone is told what that is where they are, because "13:00 Paris" is the kind of
  // detail a person gets wrong once and then misses the window.
  const hourAt = (iso, tz) => {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleTimeString([], tz ? { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: tz }
                                       : { hour: "2-digit", minute: "2-digit", hour12: false });
  };
  function untilText(iso) {
    const mins = Math.round((new Date(iso).getTime() - Date.now()) / 60000);
    if (!Number.isFinite(mins) || mins <= 0) return "";
    if (mins < 60) return `in ${mins} min`;
    const h = Math.floor(mins / 60), m = mins % 60;
    return m ? `in ${h} h ${m} min` : `in ${h} h`;
  }
  function searchStatusBar(d) {
    // The window in Paris, and the same instant where the reader is — shown only when they differ.
    const parisOpen = hourAt(d.opens_at, d.tz), parisClose = hourAt(d.closes_at, d.tz);
    const hereOpen = hourAt(d.opens_at), hereClose = hourAt(d.closes_at);
    const elsewhere = hereOpen !== parisOpen;
    const timetable = `every day ${String(d.from_hour).padStart(2, "0")}:00–${String(d.to_hour).padStart(2, "0")}:00 Paris time`;
    let dot = "closed", head = "", sub = "";
    if (!d.configured) {
      head = "Patent search is not set up on this computer";
      sub = "Nothing can leave this computer until it is. You can still work on a disclosure.";
    } else if (d.mode === "always") {
      // A MACHINE THAT KEEPS NO TIMETABLE IS NEVER GIVEN ONE. Every sentence below names opening hours,
      // and on 2026-10-01 the search enclave was deployed to run continuously while this page still had a
      // 13:00–15:00 window compiled in — so it would have told a client "closed until 13:00" about a
      // machine that was up. A confident timetable is worse than none: nobody questions a timetable.
      if (d.reachable) {
        dot = "open";
        head = "Search is available";
        sub = "";
      } else if (d.found === false) {
        dot = "trouble";
        head = "Search is not available from this computer";
        sub = "The search machine cannot be found at the address this computer is set up to use. "
          + "It needs looking at. Everything else on this page works as usual.";
      } else {
        dot = "trouble";
        head = "Search is not answering";
        sub = "It runs continuously, so this is not a closing time — try again in a few minutes. "
          + "Nothing is lost if a search cannot start.";
      }
    } else if (d.open_now && d.reachable) {
      dot = "open";
      head = `Search is open until ${parisClose} Paris time`;
      sub = (elsewhere ? `That is ${hereClose} where you are. ` : "") + `Open ${timetable}.`;
    } else if (d.found === false) {
      // Not "closed until 13:00": this machine's address cannot be found at all, so an opening time would
      // be an invention. A person told a comforting timetable waits; a person told this asks.
      dot = "trouble";
      head = "Search is not available from this computer";
      sub = "The search machine cannot be found at the address this computer is set up to use. This is not "
        + "the timetable — it needs looking at. Everything else on this page works as usual.";
    } else if (d.open_now && !d.reachable) {
      dot = "trouble";
      head = "Search should be open now, but it is not answering";
      sub = `It is scheduled ${timetable}. Try again in a few minutes; nothing is lost if a search cannot start.`;
    } else if (d.reachable) {
      dot = "open";
      head = "Search is answering, outside its usual hours";
      sub = `It normally runs ${timetable}.`;
    } else {
      head = `Search is closed — opens ${untilText(d.opens_at) || "shortly"}`;
      sub = `Next at ${parisOpen} Paris time${elsewhere ? ` (${hereOpen} where you are)` : ""}, ${timetable}.`;
    }
    const bar = el("div", `search-status ${dot}`, el("span", "status-dot"),
      el("div", "", el("div", "status-head", head), el("div", "sub", sub)));
    // Availability is not verification, and a green line could be read as "checked and safe". The machine
    // is verified against the signed reference when a search actually runs, not by this page.
    if (d.reachable) bar.append(el("span", "sub status-aside", "Availability only — the machine is checked when a search runs."));
    return bar;
  }
  async function mountSearchStatus(host) {
    const slot = el("div", "");
    host.append(slot);
    const paint = async () => {
      let d;
      try { d = await api("/api/search-status"); } catch (_) { return; }
      clear(slot);
      slot.append(searchStatusBar(d));
    };
    await paint();
    if (!watching.has("search-status")) watching.set("search-status", setInterval(paint, 60000));
  }

  // ONE definition of a matter card.
  function matterCard(m) {
    const open = () => { location.hash = `#/matter/${enc(m.id)}`; };
    const start = button(m.needs_review ? "Review draft" : "Start a session", "primary start-session", (ev) => {
      ev.stopPropagation();
      if (m.needs_review) open(); else startSession(m.id, open);
    });
    const body = el("div", "matter-body",
      el("div", "matter-title", el("span", "client", m.client), el("span", "", " / "), el("b", "", m.matter)),
      el("div", "sub", `date bound ${m.date_bound || "—"}`),
      m.needs_review ? el("div", "warn-text", "Draft · needs disclosure and date review") : null,
      el("div", "stats",
        el("span", "", plural(m.sessions, "session", "sessions")),
        el("span", "", plural(m.searches, "search", "searches")),
        el("span", "", plural(m.marks, "mark", "marks")),
        m.disclosure_words ? el("span", "", `${m.disclosure_words} words`) : el("span", "warn-text", "no disclosure yet")),
      el("div", "sub", m.sessions ? `last session ${localTime(m.last_activity)}` : `created ${localTime(m.created_at)}`),
      el("div", "matter-open", "Open this matter →"));
    const cardNode = el("div", "matter-card clickable", body, el("div", "matter-foot", start));
    cardNode.tabIndex = 0;
    cardNode.setAttribute("role", "link");
    cardNode.setAttribute("aria-label", `Open ${m.client} / ${m.matter}`);
    body.addEventListener("click", open);
    cardNode.addEventListener("keydown", (e) => {
      if (e.target === cardNode && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); open(); }
    });
    return cardNode;
  }

  async function renderMatters() {
    const p = page();
    let data;
    try { data = await api("/api/overview"); } catch (e) { return; }
    clear(p);
    p.append(el("div", "page-head", el("h1", "", "Matters"),
      el("p", "sub", "Each matter is one invention: its disclosure, its sessions with the assistant, and the records you keep.")));
    mountSearchStatus(p);
    // This page is the version the server started with. When a newer one is installed, say so rather than let
    // the difference show up as a button that fails.
    if (data.update_waiting) {
      p.append(el("div", "update-note", el("b", "", "A newer version of Probant is installed. "),
        "To use it, restart Probant home: press Ctrl+C in the terminal it runs in, then run ir probant home again. "
        + "Sessions started from this page end with it, so finish them first."));
    }
    for (const l of data.running || []) {
      p.append(el("div", "running-row", el("span", "", `Session for ${l.matter}: `),
        l.state === "ready" ? button("Open the session", "primary small", () => openLocal(l.url)) : el("span", "sub", "starting…"),
        l.state === "ready" ? button("End it", "ghost small", async () => {
          if (!(await confirmBox("End this session?",
                "The session stops and its page closes. Searches and marks already recorded are kept."))) return;
          try { await api("/api/sessions/end", { id: l.matter }); toast("Session ended.", "info"); refresh(); }
          catch (e) { toast(`Could not end it: ${e.message}`, "error"); }
        }) : null));
    }
    try {
      const readings = (await api("/api/intakes")).documents || [];
      if (readings.length) {
        const history = el("details", "fold", el("summary", "", "Recent document readings"));
        for (const reading of readings) {
          history.append(el("div", "row", button(reading.source_name, "link", () => {
            location.hash = `#/document/${enc(reading.id)}`;
          }), el("span", "sub", `${reading.drafts || 0} drafts · ${localTime(reading.staged_at)}`)));
        }
        p.append(history);
      }
    } catch (e) {
      p.append(el("p", "form-error", `Document reading history could not be loaded. ${e.message}`));
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
    for (const m of data.matters) grid.append(matterCard(m));
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
      m.needs_review ? button("Review draft", "primary", () => reviewDraftDialog(m, refresh))
        : button("Start a session", "primary", () => startSession(m.id, refresh)),
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
    if (m.needs_review) p.append(el("p", "warn-text", "Created from your document. Review the disclosure and date before starting a search."));
    if (m.running) p.append(launchBox(m.id, m.running, refresh));

    p.append(el("h2", "section", "Sessions"));
    if (!m.sessions.length) p.append(el("p", "sub", "No sessions yet. Start one: the assistant reads the disclosure and surveys published patents with you."));
    else p.append(sessionTable(m.sessions.map((s) => ({ ...s, matter: m.id })), false));

    // A cleared mark is a row in the store's history, not a mark: the professional asked for NO opinion on
    // that document. Counted here it would show as a fourth kind ("US-X · cleared") and inflate the total,
    // which is the shape of bug where an unknown value is treated as a judgement.
    const markEntries = Object.entries(m.marks || {}).filter(([, v]) => v && v !== "cleared");
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
        para("Start a session from the matter. The assistant program runs on this computer. Before sending text, this computer checks the sealed hardware for the AI model and the patent search service, then encrypts text to their keys."),
        list("The session opens in its own tab. The panel on the right says what protects the matter, in plain words, with the technical detail one click away.",
          "Connections checked means the available services passed their hardware checks and the assistant works in a closed box: no internet, and no files beyond the matter's folder. It is not an independent audit verdict.")),
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
        list("Text sent to the AI model or patent search service is encrypted to hardware this computer checked first.",
          "The network carries ciphertext; timing and message sizes remain visible. Software inside the machines handles plaintext.",
          "Browser conversations are kept with the matter on this computer, readable only by your account. Terminal sessions keep their searches, not the conversation.")),
      sec("What it can't prove",
        list("Hardware checks do not prove that software inside a machine cannot retain or disclose plaintext. Cloud platform components inside that boundary remain part of the trust set.",
          "The AI check measures firmware and start-up, not its whole filesystem. The search fingerprint matches a reference; an independent proof from source to the deployed image is still missing.",
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
  // The browser reads the file and posts text to the local home server. The reading session then sends
  // that text encrypted to the checked AI model; it has no patent-search tool.
  function readDocumentDialog() {
    const client = input("text", "e.g. Personal or Acme");
    client.value = "Personal";
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
      err.textContent = "";
      if (!/\.(txt|md|text)$/i.test(f.name)) {
        err.textContent = "Choose a .txt or .md file. For a PDF or Word document, copy its text and paste it below.";
        file.value = "";
        return;
      }
      if (f.size > 16000000) {
        err.textContent = "This file is too large. Choose a smaller text file or paste the relevant section below.";
        file.value = "";
        return;
      }
      try {
        text.value = await f.text();
        picked = f.name;
        chosen.textContent = `${f.name} · ${text.value.length.toLocaleString()} characters`;
      } catch (e) { err.textContent = "Could not open that file. Try choosing it again, or paste its text below."; }
    });
    text.addEventListener("input", () => { err.textContent = ""; text.removeAttribute("aria-invalid"); });
    const go = button("Read it", "primary", async () => {
      err.textContent = "";
      const body = text.value.trim();
      if (!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/.test(client.value.trim())) {
        err.textContent = "Enter a client name, for example Personal. Use letters, numbers, spaces, dots, dashes or underscores (up to 64 characters).";
        client.focus(); return;
      }
      if (!body) { err.textContent = "Choose a text file, or paste the document below."; text.setAttribute("aria-invalid", "true"); text.focus(); return; }
      if (text.value.length > 4000000) {
        err.textContent = "This document is too long (maximum 4 million characters). Split it or paste the relevant section.";
        text.setAttribute("aria-invalid", "true"); text.focus(); return;
      }
      go.disabled = true;
      go.textContent = "Staging…";
      try {
        const r = await api("/api/intake", { text: text.value, name: picked || "pasted document", client: client.value.trim() });
        closeDialog();
        location.hash = `#/document/${enc(r.id)}`;
      } catch (e) { err.textContent = `Could not start reading the document. ${e.message}`; go.disabled = false; go.textContent = "Read it"; }
    });
    dialog("Read a document", [
      el("p", "", "The AI reads your document and creates one draft matter per invention, with a complete summary and supporting passage. "
        + "You review each disclosure and date before searching. No searches start automatically."),
      field("Create drafts under this client", client, "Use Personal for your own work. Existing matters are kept."),
      field("Document", file, "A .txt or .md file. Read locally, then sent encrypted to the checked AI model. No patent search runs during reading."),
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
      p.append(el("p", "sub", "Findings appear here as the document is read. A long document takes a few minutes."));
      watchDocument(id);
    }
    if ((d.drafts || []).length) {
      p.append(el("h2", "section", "Draft matters created"));
      for (const draft of d.drafts) {
        const details = el("details", "fold", el("summary", "", "AI description and supporting passage"),
          el("p", "", draft.summary), el("blockquote", "quote", draft.quote));
        p.append(el("div", "card proposal", el("h3", "", draft.title),
          el("p", "sub", draft.needs_review ? "Needs disclosure and date review" : "Reviewed"),
          details, button(draft.needs_review ? "Review draft" : "Open matter", "primary small", () => {
            location.hash = `#/matter/${enc(draft.id)}`;
          })));
      }
    }
    if (d.proposals.length) p.append(el("h2", "section", "Proposed matters"));
    if (!d.proposals.length && !(d.drafts || []).length) {
      p.append(el("p", "sub", d.running ? "No findings yet." : "This reading has no saved findings."));
    }
    for (const [i, pr] of d.proposals.entries()) {
      const card = el("div", "card proposal",
        el("div", "card-head", el("span", "title", pr.title),
          pr.priority_date ? el("span", "sub", `priority date ${pr.priority_date}`) : el("span", "sub", "")),
        el("div", "card-body", el("p", "", pr.summary),
          el("blockquote", "quote", pr.quote),
          el("p", "sub", "The supporting passage was matched to the document. Review the AI's summary against it before creating a matter.")),
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
    const validation = formErrors({ client, matter, priority_date: date });
    const err = el("p", "form-error");
    const go = button("Open the matter", "primary", async () => {
      err.textContent = "";
      if (!validation.validate()) return;
      go.disabled = true;
      try {
        const r = await api("/api/intake/create", { id, index, client: client.value, matter: matter.value,
                                                    priority_date: date.value });
        closeDialog();
        toast(`Matter ${r.id} opened.`, "info");
        location.hash = `#/matter/${enc(r.id)}`;
      } catch (e) {
        if (Object.keys(e.fields || {}).length) validation.show(e.fields);
        else err.textContent = `Could not create the matter from this proposal. ${e.message}`;
        go.disabled = false;
      }
    });
    dialog(`Open "${proposal.title}" as a matter`, [
      el("p", "", "The AI's draft summary becomes the disclosure, with its source passage. Review it before starting a search."),
      validation.field("client", "Client", "Required. Use Personal if this is for yourself."),
      validation.field("matter", "Matter", "Required. You can change the suggested name."),
      validation.field("priority_date", "Priority date", "Only documents published before this date are searched. Check any date suggested by the AI."),
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

    // The public key used to be a wall of JSON sitting open on the page, with the button that actually does
    // the job small and underneath it. That reads as something you are supposed to understand before you
    // dare touch it. The order is inverted here: one obvious action, the reassurance beside it, and the raw
    // text folded away for whoever wants to look. Nothing about what is sent changed.
    p.append(el("h2", "section", "Your public key"));
    const cardText = JSON.stringify(d.card, null, 1);
    const raw = el("textarea", "card-box", cardText);
    raw.readOnly = true;              // there is nothing here to edit, and an edit could only break it
    raw.spellcheck = false;
    p.append(el("div", "fingerprint-card",
      el("div", "sub", "Your fingerprint — read these four groups aloud to them, and check theirs the same way."),
      el("div", "fingerprint", d.fingerprint),
      el("div", "row",
        button("Copy my public key", "primary", () => navigator.clipboard.writeText(cardText)
          .then(() => toast("Copied — paste it into an email to them.", "info"))
          // A copy that quietly fails is worse than one that refuses: the person emails nothing and does
          // not find out until the other side says the key never arrived.
          .catch(() => toast("Could not reach the clipboard. Open \u201cShow the raw text\u201d below and copy it by hand.", "error")))),
      el("p", "sub", "Send it to them however you like — email is fine. It holds public keys only: anyone "
        + "who reads it learns nothing and can decrypt nothing, and your private keys never leave this computer."),
      el("details", "card-reveal", el("summary", "", "Show the raw text"), raw)));

    // Deliveries — what has actually gone out and come in. Without this the page can seal a corpus and
    // open one while showing no sign that either happened.
    p.append(el("h2", "section", "Deliveries"));
    if (!(d.corpora || []).length) {
      p.append(el("p", "sub", "Nothing sent or received yet. A delivery is matters sealed together with "
        + "the documents that describe them; it keeps its own identity on both sides."));
    }
    for (const c of d.corpora || []) {
      const sent = c.direction === "sent";
      const who = sent ? `to ${c.to || "?"}` : `from ${c.from_name || c.from || "unknown sender"}`;
      // A delivery signed by a key that is not one of your contacts. That IS worth flagging — but the
      // first delivery anyone receives is necessarily from someone they have not added yet, so phrasing it
      // as an alarm makes the expected case look like an attack. It is stated calmly, with the thing to do.
      const unknown = !sent && !c.known_contact;
      const warn = unknown ? el("span", "sub soft-warn", "sender not saved yet") : el("span", "");
      // The detail lines go INSIDE the row: appended to the page they floated under the card, and with
      // two deliveries listed there would be no way to tell which one they described.
      const detail = el("div", "");
      detail.append(el("div", "mono sub", c.id));
      if ((c.files || []).length) detail.append(el("div", "sub", `documents: ${c.files.join(", ")}`));
      if ((c.matters || []).length) detail.append(el("div", "sub", `matters: ${c.matters.join(", ")}`));
      if (unknown) detail.append(el("div", "sub", "The fingerprint beside this is the key that signed it. "
        + "Check it with them by voice, then add them under \u201cPeople you can share with\u201d — you need "
        + "their public key to send anything back."));
      p.append(el("div", "record-row",
        el("span", "", c.name || "(unnamed)"),
        detail,
        el("span", "sub", `${sent ? "sent" : "received"} · ${who}`),
        warn));
    }

    p.append(el("h2", "section", "People you can share with"));
    if (!d.contacts.length) p.append(el("p", "sub", "Nobody yet. Add someone using the public key they sent you."));
    for (const c of d.contacts) {
      const remove = button("Remove", "ghost", async () => {
        remove.disabled = true;
        try {
          await api("/api/sharing/contact/remove", { name: c.name, fingerprint: c.fingerprint });
          toast(`${c.name} removed. You can add their public key again.`);
          await renderSharing();
        } catch (e) {
          toast(e.message, "error");
          remove.disabled = false;
        }
      });
      remove.setAttribute("aria-label", `Remove ${c.name}`);
      remove.title = "Remove this saved contact; existing deliveries are kept";
      p.append(el("div", "record-row", el("span", "", c.name), el("span", "mono sub", c.fingerprint),
        el("span", "sub", `added ${localTime(c.added_at)}`),
        el("div", "row",
          el("span", c.key_valid ? "sub" : "warn-text", c.key_valid ? "✓ Key format checked" : "Key needs attention"),
          remove)));
    }
    p.append(el("div", "row", button("Add someone", "ghost", () => addContactDialog(() => renderSharing())),
      button("Open a delivery sent to you", "ghost", () => openShareDialog())));

    p.append(el("h2", "section", "Send matters"));
    if (!d.contacts.length) {
      p.append(el("p", "sub", "Add someone first: a corpus is sealed to their key, so you need their public key."));
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
    const includeMarks = input("checkbox");
    const result = el("div", "share-result");
    result.hidden = true;
    const go = button("Seal and write the file", "primary", async () => {
      if (!chosen.size) { toast("Choose at least one matter.", "error"); return; }
      go.disabled = true;
      try {
        const r = await api("/api/sharing/share", { to: to.value, matters: [...chosen], note: note.value,
                                                    documents: [...docs], corpus_name: corpusName.value,
                                                    include_marks: includeMarks.checked });
        clear(result);
        result.hidden = false;
        result.append(el("div", "", el("b", "", `${r.matters} matter(s)`
          + (r.documents && r.documents.length ? ` and ${r.documents.length} document(s)` : "")
          + ` ready to send to ${to.value}`),
          ` (${r.to_fingerprint}), signed as ${r.from_fingerprint}.`),
          el("p", "sub", r.marks_shared ? `${plural(r.marks_shared, "mark", "marks")} included as your judgments.` : "No marks included."),
          el("span", "mono", r.path),
          el("p", "", "Saved on this computer; it has not been sent. Send this file by email, a shared folder or USB. "
            + "They save it, then choose Sharing → Open a delivery sent to you in Probant."),
          el("p", "sub", "Encrypted to their key, with a copy sealed to you so you can reopen what you sent."),
          button("Copy the path", "ghost small", () => navigator.clipboard.writeText(r.path)
            .then(() => toast("Copied.", "info")).catch(() => {})));
      } catch (e) { toast(e.message, "error"); } finally { go.disabled = false; }
    });
    const corpusName = input("text", "e.g. InferRoute cluster — 9 filings + surplus");
    p.append(list);
    if ((d.documents || []).length) {
      p.append(el("h2", "section", "Documents about the whole corpus"),
        el("p", "sub", "These describe the cluster rather than any one matter — a matter list, a reading "
          + "guide. They quote the filings, so they are sealed with the matters, never attached to an email."),
        docBox);
    }
    p.append(field("Send to", to), field("Name this corpus", corpusName), field("A note for them", note),
             el("label", "row", includeMarks, el("span", "", "Include my marks")),
             el("div", "row", go), result);
  }

  // Adding someone was an empty textarea under a paragraph warning about impostors: the one step in this
  // product where a person is asked to handle a key by hand, presented at its least approachable. The box
  // now takes a file or the clipboard as readily as a paste, and answers as soon as it has something — the
  // fingerprint comes back from the server, derived by the same code that will record it, so the number
  // read aloud here is the number stored. The warning has not gone; it moved to the moment it applies,
  // beside a fingerprint the person can actually read out, instead of guarding an empty box.
  function addContactDialog(onAdded) {
    const name = input("text", "e.g. betrancourt");
    const card = input("textarea", "Paste their key here, or drop the file they sent you.");
    card.rows = 5;
    card.spellcheck = false;
    const verdict = el("p", "card-verdict");
    const err = el("p", "form-error");
    const go = button("Add", "primary", async () => {
      err.textContent = "";
      try {
        const r = await api("/api/sharing/contact", { name: name.value, card: card.value });
        closeDialog();
        toast(`Key format checked. ${r.name} saved — fingerprint ${r.fingerprint}`, "info");
        onAdded();
      } catch (e) { err.textContent = e.message; }
    });
    go.disabled = true;               // nothing to add until the box actually holds a key

    // Each check is tagged, because a slow answer about earlier text must not overwrite a newer verdict.
    let token = 0;
    async function check() {
      const mine = ++token;
      const text = card.value.trim();
      clear(verdict);
      verdict.className = "card-verdict";
      go.disabled = true;
      if (!text) return;
      let r;
      try { r = await api("/api/sharing/contact/preview", { card: text }); } catch (_) { return; }
      if (mine !== token) return;
      if (r.ok) {
        verdict.className = "card-verdict good";
        verdict.append(el("b", "", `✓ Key format valid · fingerprint ${r.fingerprint}`),
          " — confirm this fingerprint with them before sending. This checks the key card, not the person's identity.");
        go.disabled = false;
      } else if (r.reason) {
        verdict.className = "card-verdict hint";
        verdict.textContent = r.reason;
      }
    }
    card.addEventListener("input", check);

    function loadFile(f) {
      if (!f) return;
      const rd = new FileReader();
      rd.addEventListener("load", () => { card.value = String(rd.result || ""); check(); });
      rd.readAsText(f);
    }
    const picker = document.createElement("input");
    picker.type = "file";
    picker.accept = ".json,.txt,application/json,text/plain";
    picker.addEventListener("change", () => loadFile(picker.files && picker.files[0]));
    card.addEventListener("dragover", (e) => { e.preventDefault(); card.classList.add("dropping"); });
    card.addEventListener("dragleave", () => card.classList.remove("dropping"));
    card.addEventListener("drop", (e) => {
      e.preventDefault();
      card.classList.remove("dropping");
      loadFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]);
    });

    dialog("Add someone to share with", [
      el("p", "", "They sent you a public key — a block of text, or a small file. Put it here and Probant "
        + "will tell you whose it is."),
      el("div", "row",
        button("Paste from clipboard", "ghost small", async () => {
          try { card.value = await navigator.clipboard.readText(); check(); }
          catch (_) { toast("Could not read the clipboard — paste into the box with Ctrl+V.", "error"); card.focus(); }
        }),
        button("Choose a file\u2026", "ghost small", () => picker.click())),
      field("Their key", card),
      verdict,
      field("Name", name, "What you will call them here."),
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
