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

  const { el, clear, markdown, renderCheck } = window.ProbantUI;

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

  // Compact by default (Henry, 19 Sep: "make the private certifications section more compact so that the
  // beginning of your marks is visible without scrolling"). The verdict and one line per protection stay in
  // view; each protection's points and detail sit behind its own "More", and the explanation behind a
  // labelled toggle.
  const VERDICT_WORD = { private: "Private", limited: "Partly protected", blocked: "Not opened" };
  const VERDICT_SEAL = { private: "✓", limited: "!", blocked: "✗" };
  const DOT = { ok: "✓", warn: "!", fail: "✗", off: "", info: "" };   // inside a filled dot, a plain mark reads best
  function renderTrust(t) {
    const body = $("trust-body");
    clear(body);
    const pill = $("verdict");
    pill.className = `pill pill-${t.verdict}`;
    pill.textContent = VERDICT_PILL[t.verdict] || t.verdict;
    // The verdict as a seal: one word, then the headline without repeating that word, then when it was proved.
    const word = VERDICT_WORD[t.verdict] || "";
    let line = String(t.headline || "");
    if (word && line.startsWith(word)) line = line.slice(word.length).replace(/^[:.]\s*/, "");
    if (line) line = line[0].toUpperCase() + line.slice(1);
    const at = t.checked_at ? new Date(t.checked_at) : null;
    const when = !at ? "" : at.toDateString() === new Date().toDateString()
      ? `today at ${at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })}`
      : at.toLocaleString([], { dateStyle: "medium", timeStyle: "short", hour12: false });
    body.append(el("div", `verdict ${t.verdict}`,
      el("span", "seal", el("span", "seal-mark", VERDICT_SEAL[t.verdict] || "·")),
      el("div", "verdict-text",
        el("div", "verdict-word", word || t.verdict),
        line ? el("div", "verdict-line", line) : null,
        when ? el("div", "checked", `${t.verdict === "private" ? "Hardware checked" : "Checked"} ${when}`) : null)));
    if (t.explainer) body.append(el("details", "fold", el("summary", "", "How a sealed machine keeps this private"), el("p", "explainer", t.explainer)));
    body.append(el("h2", "", "What protects this matter"));
    const chain = el("div", "chain");
    for (const it of t.items || []) {
      const head = el("div", "item-head",
        el("span", `sym ${it.state}`, DOT[it.state] ?? "", el("span", "sr", SYM[it.state] ? ` (${it.state})` : "")),
        el("span", "item-title", it.title),
        el("span", "item-summary", it.summary));
      const points = it.points && it.points.length ? it.points : [];
      const hasMore = points.length || (it.more && it.more.length) || (it.technical && it.technical.length);
      const item = el("div", `item ${it.state}`, head);
      if (hasMore) {
        const more = el("div", "more");
        more.hidden = true;
        if (points.length) more.append(el("ul", "item-points", ...points.map((p) => el("li", "", p))));
        for (const p of it.more || []) more.append(el("p", "", p));
        if (it.technical && it.technical.length) {
          const table = el("table", "tech");
          for (const r of it.technical) {
            table.append(el("tr", "", el("td", `sym ${r.ok ? "ok" : "fail"}`, r.ok ? "✓" : "✗"),
              el("td", "", el("div", "", r.label), el("div", "v", r.value))));
          }
          more.append(el("p", "tech-title", `Technical detail (${it.technical.length})`), table);
        }
        // The whole row opens its detail; the chevron is the visible, focusable handle.
        const toggle = el("button", "more-toggle", "More");
        toggle.type = "button";
        toggle.setAttribute("aria-expanded", "false");
        const flip = () => {
          more.hidden = !more.hidden;
          toggle.textContent = more.hidden ? "More" : "Less";
          toggle.setAttribute("aria-expanded", String(!more.hidden));
          item.classList.toggle("open", !more.hidden);
        };
        toggle.addEventListener("click", (e) => { e.stopPropagation(); flip(); });
        head.addEventListener("click", (e) => { if (!e.target.closest("a, button")) flip(); });
        item.classList.add("expandable");
        head.append(toggle, more);
      }
      chain.append(item);
    }
    body.append(chain);
    if (t.control_note) body.append(el("p", "control-note", t.control_note));
    // The limits are not repeated here (Henry, 19 Sep: "not needed or even relevant here"). They are said
    // where they matter, in the exported record the professional hands on, and in the terminal card.
  }


  // ── conversation ──
  const log = $("log");
  let current = null;       // the assistant message being streamed: {node, text}
  let renderQueued = false;
  const cards = new Map();  // ev.call (the bridge's wire name for a tool call) → card elements
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

  auditOffer($("audit"));            // standing offer in the panel, not a step hidden behind the export

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
    if (!ev.stopped && current.text.trim()) {
      failedTries = 0;
      // An answer got through, so the hiccup is over: clear the muted line and give the NEXT one a
      // full budget. Without this reset a single bad minute would leave every later blip loud.
      autoTries = 0;
      if (quietNode && quietNode.isConnected) { quietNode.remove(); quietNode = null; }
    }
    renderCurrent();
    // On END only, not per delta: a streaming paragraph can split a publication number across two chunks,
    // and linkifying a half-written one would make "US-20151" a button to nothing.
    linkifyPubNos(current.node);
    if (!current.text.trim()) current.node.remove();
    if (ev.stopped === "error") showError(ev.error || "");
    if (ev.stopped === "aborted") log.append(el("div", "step", "Stopped."));
    current = null;
  }

  // An error from the AI's side, said plainly, with the raw detail one click away. The same error repeated
  // (the agent retries) updates one line instead of stacking.
  let lastError = null;
  // EVERY FAILURE THE LANE CAN REPORT, matched on OUR OWN sanitised phrases rather than on status
  // numbers. The lane never passes an upstream body through (a 402 body once reached a user carrying a
  // crypto wallet address), so what arrives is one of a bounded set of sentences this product writes —
  // and matching those is exact, where matching "502" catches any sentence that happens to contain it.
  //
  // Before this, five of the ten provider statuses fell through to "didn't answer this request", the
  // blandest sentence here, including 402 — the one status that tells you the actual problem. And
  // 401/403 ("our credentials were refused") matched /refus/ and were reported as a VERIFICATION
  // failure: a billing problem shown as a broken trust chain. Henry saw the fallthrough four times.
  //
  // Order is by specificity. Each entry is [test, sentence]; the first match wins.
  const MODEL_ERROR_CASES = [
    // ── lane-internal: our own conditions, most specific first ────────────────────────────────
    [(d) => d.includes("no verified alternative") || d.includes("instance is gone") || d.includes("no-eligible-instance"),
     "No verified AI machine was free just then, so nothing was sent in the clear. That is a capacity limit, not a failed check — the session tries another verified machine by itself."],
    [(d) => /not verified|not be verified|unverified|verification failed|refusing to continue/.test(d),
     "The AI machine could not be verified, so nothing was sent to it."],
    // A nonce rejected TWICE, one of them from a fresh pool, is not an expiry — we already did the thing
    // the expiry message tells the reader to wait for. Checked before the ordinary nonce case.
    [(d) => d.includes("nonce twice") || d.includes("rejected our request nonce twice"),
     "The AI machine rejected this session's one-time keys twice, including a fresh one, so nothing was sent. Retrying will not clear it — start a fresh session on this matter."],
    [(d) => d.includes("nonce"),
     "The AI machine turned this request away because its one-time key had expired. Try again; a fresh key is fetched automatically."],
    // ── MID-STREAM: after the reply has started. These four were invisible to this list until
    // 2026-09-30, because every earlier case describes a failure to SEND. Once the enclave is already
    // answering, the lane's retry-on-another-instance is behind us — _send_sealed has returned — so these
    // cannot be recovered by it, which is why `upstream_retries` read 0 across 26 sessions including one
    // with 28 errors. They are still safe to retry from the page: nothing went out in the clear either way.
    // ── PI'S OWN conditions. The detail is Pi's `message.errorMessage`, NOT a sentence this lane wrote
    // — a premise the comment above got wrong. Pi carries 338 distinct error strings, so most of what
    // arrives here is unmatchable by construction, and that is the real reason the unnamed sentence was
    // common. These two are the ones worth naming because retrying them is WORSE than showing them.
    [(d) => d.includes("context overflow") || d.includes("reducing context") || d.includes("larger-context"),
     "This conversation has grown too long for the AI machine to hold. Nothing was sent in the clear. "
     + "Start a fresh session on this matter — your searches, marks and this conversation stay with it."],
    [(d) => d.includes("compaction failed"),
     "The AI machine could not shorten this conversation to make room, so nothing was sent. "
     + "Start a fresh session on this matter; nothing is lost."],
    [(d) => d.includes("ended part-way") || d.includes("without finishing the answer"),
     "The AI machine's answer stopped part-way through, so nothing was sent in the clear. Continuing picks up where it left off."],
    [(d) => d.includes("mid-reply"),
     "The connection to the AI machine dropped while it was answering. Nothing was sent in the clear; continuing resumes it."],
    [(d) => d.includes("could not open the enclave"),
     "This machine could not open the AI machine's reply, so the answer was discarded rather than shown unverified. Nothing was sent in the clear."],
    [(d) => d.includes("relay is unreachable") || d.includes("could not seal") || d.includes("could not be sent"),
     "The AI machine couldn't be reached. Nothing was sent in the clear; try again in a minute."],
    // ── the provider's own outcome, via UPSTREAM_PUBLIC in the lane ───────────────────────────
    [(d) => d.includes("out of capacity"),
     "The sealed AI lane is out of capacity right now, so nothing was sent. This is an account limit rather than a fault: another model is tried automatically, and if you keep seeing this the lane needs topping up."],
    [(d) => d.includes("credentials were refused"),
     "The AI provider refused our credentials, so nothing was sent. That is a problem at our end, not with your matter or your machine."],
    [(d) => d.includes("rate-limited") || d.includes("429"),
     "The AI machine is busy right now. Wait a moment and try again."],
    [(d) => d.includes("temporarily unavailable") || d.includes("provider failed") || d.includes("provider timed out") || d.includes("timed out"),
     "The AI provider is having trouble right now, so nothing was sent. Another machine is tried automatically; if it persists, wait a few minutes."],
    [(d) => d.includes("model or route was not found"),
     "That model is not available on the sealed lane right now, so nothing was sent. Another one is tried automatically."],
    [(d) => d.includes("rejected as malformed"),
     "The AI provider rejected the request as malformed, so nothing was sent. This is a fault at our end; starting a fresh session usually clears it."],
    // The agent's HTTP client could not reach this machine's own verifying proxy: its request never got
    // as far as being sealed. LAST in the list on purpose — it is the least specific wording any client
    // can produce, so an earlier case that knows more must win. Named rather than left unnamed because
    // the honest thing to say about it is stronger than the generic sentence: nothing was sent because
    // nothing was ever SENT, and this one really does clear by itself.
    [(d) => d.includes("connection error") || d.includes("econnreset") || d.includes("socket hang up")
            || d.includes("fetch failed") || d.includes("epipe"),
     "This machine's own connection to the checking step dropped before the request left it, so nothing "
     + "was sent in the clear and the AI machine never saw it. Continuing retries it."],
  ];

  // The sentence for a failure this page could not name. Named so isTransient can ASK whether we
  // recognised the failure, instead of keeping a second token list that can disagree with this one.
  const UNNAMED_FAILURE = "The AI machine did not complete this request, and nothing was sent in the clear.";

  function plainModelError(detail) {
    const d = String(detail || "").toLowerCase();
    for (const [test, sentence] of MODEL_ERROR_CASES) if (test(d)) return sentence;
    // Anything unanticipated stays honest rather than being guessed at, and says nothing left the machine.
    return UNNAMED_FAILURE;
  }

  const RETRY_TEXT = "Continue where you left off";
  let failedTries = 0;                  // failed answers in a row; an answer that gets through resets it

  // TRANSIENT vs SUBSTANTIVE. A transport hiccup where NOTHING left this machine is not news: the honest
  // response is to try again, not to hand the professional a red block and a button. Henry, 30 Sep: "we get
  // this too often, it's not looking good — maybe more discreet or even silent."
  //
  // What is NEVER transient: a machine that could not be VERIFIED. That refusal is the product working, and
  // quietly retrying it would train someone to ignore the one message that must always be read. It is
  // excluded here explicitly rather than by omission, so a later edit to the list cannot swallow it.
  // Failures no retry can clear. Kept separate from MODEL_ERROR_CASES because the question "can this
  // clear?" is not the question "what do we call it?" — a failure can be unnameable and still terminal.
  const TERMINAL = [
    /nonce twice|rejected our request nonce twice/,      // already tried a fresh pool; it said so
    /context overflow|reducing context|larger-context/,  // retrying adds to the context that overflowed
    /compaction failed/,                                  // the room-making step is what failed
  ];
  function isTerminal(detail) {
    const d = String(detail || "").toLowerCase();
    return TERMINAL.some((re) => re.test(d));
  }

  function isTransient(detail) {
    const d = String(detail || "").toLowerCase();
    // Verification named explicitly, not by the bare token "refus". A behavioural sim caught that
    // "connection refused" — an ordinary socket error — was being read as a verification refusal and shown
    // loudly, while the tokens below would have called it transient. The two senses of "refused" are
    // different events and the check has to tell them apart.
    if (/not verified|unverified|could not be verified|verification failed|refused to seal/.test(d)) return false;
    // Any OTHER refusal is a decision, not a hiccup: it stays loud. A socket refusal is exempted by name.
    if (d.includes("refus") && !/connection refused|econnrefused/.test(d)) return false;
    // TERMINAL: the condition cannot clear by trying again, and its own words usually say so. Retrying
    // these is not merely wasted — for a context overflow each retry ADDS a message to the context that
    // just overflowed, and hides the one sentence telling the reader what to do.
    //
    // This generalises a case found on 2026-09-30 rather than repeating it: a nonce rejected TWICE, one
    // from a fresh pool, was falling into the bare "nonce" token below and being quietly retried against
    // the advice it was about to print. That was an instance of this class, not a special case.
    if (isTerminal(d)) return false;
    // A REPLY THAT WILL NOT OPEN IS NEVER QUIET. It is an authentication failure against the key the
    // hardware quote committed to — indistinguishable from a substituted key or machine, and the only
    // runtime sign that the claim "no relay could substitute the key or the hardware without failing a
    // check on this device" is being tested. I made this one quiet earlier tonight while fixing the
    // mid-stream classes; retrying it silently and averaging it into a health score turns the one
    // tripwire this product has into a metric.
    if (d.includes("could not open the enclave")) return false;
    if (d.includes("unreachable") || d.includes("502") || d.includes("503")
        || d.includes("504") || d.includes("timeout") || d.includes("timed out")
        || d.includes("429") || d.includes("rate") || d.includes("nonce")
        || d.includes("connection") || d.includes("econn")) return true;
    // TRANSPORT BETWEEN THE AGENT AND THIS MACHINE. Listed by name rather than left to the default
    // below, because NAMING a failure takes away its quiet retry: the default is "we could not name it",
    // so the moment wording was added for these they became loud. A sim caught that the same edit that
    // made the sentence honest made the page shout it.
    if (d.includes("socket hang up") || d.includes("fetch failed") || d.includes("epipe")
        || d.includes("broken pipe")) return true;
    // Mid-stream: the reply started and did not finish. Retrying is the right move and nothing left the
    // machine in the clear either way.
    if (d.includes("ended part-way") || d.includes("without finishing the answer")
        || d.includes("mid-reply")) return true;
    // UNRECOGNISED IS NOT EVIDENCE OF SUBSTANTIVE. Henry, 30 Sep, on seeing the unnamed sentence in a
    // session that then continued normally: "really i guess that message should not have been displayed".
    //
    // The default was backwards. A failure this page could NOT name was shown loudly and permanently,
    // while every failure it could name got a considered verdict — so the case where we know least
    // produced the most alarming output. Not recognising a sentence says something about this list, not
    // about the severity of what happened.
    //
    // The verification and refusal exclusions above run FIRST and are unaffected: a machine that could not
    // be verified is never quiet, whether or not we have wording for it. And this is a retry BUDGET, not
    // silence — AUTO_RETRIES exhausted still escalates to the block, so a failure that does not clear is
    // still reported.
    return plainModelError(detail) === UNNAMED_FAILURE;
  }
  const AUTO_RETRIES = 2;               // then stop and say so: silence that never resolves is worse
  let autoTries = 0;
  let quietNode = null;                 // the one muted line, reused; removed when an answer arrives
  function quietRetry(detail) {
    autoTries += 1;
    // Say WHICH attempt from the first one. A bare ellipsis that might be the last thing this session
    // ever says is worse than a line that shows where it is in a bounded budget: the reader can see the
    // page is still trying, and how much trying is left, without being handed a red block.
    const line = `Reconnecting… nothing was sent in the clear. (${autoTries} of ${AUTO_RETRIES})`;
    if (!quietNode || !quietNode.isConnected) {
      quietNode = el("div", "step quiet-retry", line);
      log.append(quietNode);
    } else {
      quietNode.textContent = line;
    }
    s();
    setTimeout(() => { if (!ended) send(RETRY_TEXT); }, 1500 * autoTries);
  }

  function showError(detail) {
    // Counted BEFORE the quiet path can return: a failure shown discreetly is still a failure, so going
    // quiet must not push the "this session is stuck / start a fresh one" offer further away. Display and
    // tally are separate decisions.
    failedTries += 1;
    // Quiet path, while there are tries left. Escalates to the block below once they run out, so a failure
    // that does not clear is still reported rather than hidden behind an ellipsis forever.
    if (isTransient(detail) && autoTries < AUTO_RETRIES && !ended) { quietRetry(detail); return; }
    if (quietNode && quietNode.isConnected) { quietNode.remove(); quietNode = null; }
    const plain = plainModelError(detail);
    if (lastError && lastError.plain === plain && lastError.node.isConnected && log.lastElementChild === lastError.node) {
      lastError.count += 1;
      lastError.counter.textContent = ` (${lastError.count} times)`;
      return;
    }
    const counter = el("span", "count", "");
    const more = el("details", "err-detail", el("summary", "", "Technical detail"), el("div", "mono", detail));
    // A way on, not just a report (Henry, 19 Sep: "I don't even have a button to retry"). It asks the assistant
    // to CONTINUE rather than resending the question: a failure after searches had already run would otherwise
    // redo them. Like every button here, it sends exactly its words.
    const again = el("button", "ghost small", RETRY_TEXT);
    again.type = "button";
    again.addEventListener("click", () => { again.disabled = true; send(RETRY_TEXT); });
    // Offered for anything that might clear; withheld when it cannot. A button that is certain to fail
    // is not a way on, it is a second way to be told no.
    const actions = el("div", "row err-actions", isTerminal(detail) ? null : again);
    // The same failure on the NEXT try too means this session is stuck, and continuing only repeats it.
    // A fresh session re-checks the AI machine from scratch — the way out of stale state, and the only way
    // out of a session started on older code (19 Sep: two sessions from before a fix kept failing while every
    // new one would have worked). Nothing is lost: searches, marks and the conversation stay with the matter.
    let hint = null;
    // A TERMINAL condition offers the way out on the FIRST failure, not the second. Waiting for a second
    // is right when we are hoping a hiccup clears; it is wrong when the condition cannot clear, because
    // it asks the reader to watch the same failure twice before showing them the door. And the hint has
    // to say the right thing: "keeps failing to reach the AI machine" is false for a conversation that
    // simply grew too long, and sends someone to check their network over a full context.
    const terminal = isTerminal(detail);
    if (failedTries >= 2 || terminal) {
      hint = el("p", "sub", terminal
        ? "Trying again will not clear this one. A fresh session starts with an empty conversation; "
          + "your searches, marks and this conversation stay with the matter."
        : "This session keeps failing to reach the AI machine. A fresh session checks it again "
        + "from scratch; your searches, marks and this conversation stay with the matter.");
      if (HOME_LINK.test(homeUrl)) {
        const fresh = el("button", "primary small", "Start a fresh session on this matter");
        fresh.type = "button";
        fresh.addEventListener("click", () => goHome(`/matter/${matterId}`));
        actions.prepend(fresh);
      }
    }
    const node = el("div", "msg-error", el("div", "", plain, counter), detail ? more : null, hint, actions);
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
  // Clicking a publication number OPENS it, by asking the assistant to read it in the sealed session.
  // Deliberately routed through the conversation rather than a side fetch: the read then happens inside the
  // attested session and lands in the record like any other operation, instead of being a lookup nothing
  // attests. Henry, 30 Sep: "if when we clicked on a patent mentioned in the text it opened".
  const OPEN_DOC = (k) => `Open ${k}: read that document and show me what it discloses`;

  const DEEPER = "Look deeper at the ones I marked relevant: search their features one at a time and find documents like them";
  const LEAVE_OUT = "Continue the survey, leaving out what I marked known or not relevant";
  // ONE definition of "a publication number you can click", used by result rows, the results panel and the
  // assistant's prose alike. Two renderings of the same affordance would drift, and the professional would
  // learn that some numbers are clickable and others are not.
  const PUBNO = /\b([A-Z]{2}-[0-9A-Z]{2,}(?:-[0-9A-Z]{1,3})?)\b/g;
  function docLink(keyNo) {
    const a = el("button", "key key-link", keyNo);
    a.type = "button";
    a.title = `Open ${keyNo}`;
    a.addEventListener("click", (e) => { e.stopPropagation(); if (!ended) send(OPEN_DOC(keyNo)); });
    return a;
  }

  // Turn publication numbers in a finished paragraph into the same clickable. Builds TEXT NODES and buttons
  // rather than assigning innerHTML: this runs over model output, and innerHTML here would make any sentence
  // it produced into markup this page executes.
  function linkifyPubNos(root) {
    if (!root) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    const todo = [];
    while (walker.nextNode()) {
      const n = walker.currentNode;
      if (n.parentElement && n.parentElement.closest(".key-link, .mono, code, pre")) continue;
      if (PUBNO.test(n.nodeValue || "")) todo.push(n);
      PUBNO.lastIndex = 0;
    }
    for (const n of todo) {
      const frag = document.createDocumentFragment();
      let last = 0;
      const text = n.nodeValue || "";
      text.replace(PUBNO, (m, k, off) => {
        if (off > last) frag.append(document.createTextNode(text.slice(last, off)));
        frag.append(docLink(k));
        last = off + m.length;
        return m;
      });
      if (last < text.length) frag.append(document.createTextNode(text.slice(last)));
      if (last > 0) n.parentNode.replaceChild(frag, n);
    }
  }

  // HOW STRONGLY THIS SEARCH MATCHED, relative to the others IN THE SAME SEARCH. A fixed k means the last
  // results are simply the weakest the pool had, not ten equally-relevant documents — measured on a real
  // search, rank 1 scored about ten times rank 12 and eight of twenty fell below zero, while the page
  // showed all twenty identically. Henry, 2026-09-30: "as if they all [have] the same-level relevance".
  //
  // NO NUMBER IS SHOWN, and there is no bar in the cross-search panel. The engine's score is a LambdaRank
  // output: an ordering signal, not a calibrated probability. It is comparable within ONE query and NOT
  // across two, so printing it would invent a precision it does not have, and comparing it between
  // searches would be simply wrong. A bar normalised inside its own search says exactly what the number
  // supports and nothing more.
  function relBar(score, lo, hi) {
    // ALWAYS A NODE, never null. The row is a four-column grid and a missing child shifts every later
    // column left by one — which is how the mark buttons ended up clipped in the 26px rank column. An
    // empty track holds the place and shows nothing.
    if (typeof score !== "number" || !isFinite(score) || !(hi > lo)) return el("span", "relbar relbar-none");
    const frac = Math.max(0.04, Math.min(1, (score - lo) / (hi - lo)));   // floor: never an invisible bar
    const bar = el("span", "relbar");
    const fill = el("span", "relbar-fill");
    fill.style.width = `${(frac * 100).toFixed(1)}%`;
    bar.append(fill);
    bar.title = "how strongly this matched, relative to the other results of this same search";
    bar.setAttribute("aria-label", bar.title);
    return bar;
  }

  function scoreRange(docs) {
    const xs = (docs || []).map((d) => d && d.score).filter((x) => typeof x === "number" && isFinite(x));
    return xs.length >= 2 ? [Math.min(...xs), Math.max(...xs)] : [NaN, NaN];
  }

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
  // ── Next steps: ONE panel above the message box ────────────────────────────────────────────────
  //
  // Henry, 19 Sep: "we have NEXT STEPS and FROM YOUR MARKS … polish the double to look more together and adapt
  // counts in a smart way", and "leverage our agent harness to improve, select and/or augment it through the
  // LLM without extra requests". So:
  //
  // - The ASSISTANT's list comes first. It has already seen your marks: the extension hands them over with
  //   your message (no extra model request) together with these same candidate steps, and the assistant
  //   keeps, rewords, merges or drops them. A deliberate drop is respected — the page does not add back what
  //   the assistant chose to leave out.
  // - The page adds steps only for marks you made AFTER the assistant took up your message — it could not
  //   have seen those — and only when its list does not already cover them.
  // - With no list from the assistant (before its first answer, or when it offered none) the steps come from
  //   all your marks; with no marks either, and once the conversation has started, plain ideas.
  // - Five buttons at most in all; marks made since the answer always keep at least one place.
  //
  // Every button shows exactly the message it sends.
  const SUMMARISE_IDEA = "Summarise what the searches have surfaced so far";
  const SURVEY = "Run a prior-art survey of the disclosure";       // worded as the extension words it
  // The deep search, worded identically in ir-attested.ts (a test holds the two together). It is drawn
  // apart from the others because it is the one button that puts SEVERAL sealed queries in one press —
  // minutes rather than seconds — and a person should be able to tell that before pressing, not after.
  const DEEP = "Search deeply: put the whole disclosure, its features, and my marks to the search machine";
  // Once a press has run, the same row asks for the follow-up shape instead. Henry, 25 Sep: after
  // marking, "it still shows this message instead of the updated one". Worded identically to the
  // extension's STEP_DEEP_FOCUSED, because the button SENDS this sentence and the assistant has to
  // recognise it as the step it offered.
  const DEEP_FOCUSED = "Search deeply again, leading with the documents I marked: read them against the disclosure and find more like them";
  // Whether this session has a search machine at all. A session without one registers no search tools, so
  // the deep button would send a sentence the assistant has no way to act on — offering an action that
  // cannot work, to someone who has not yet been told why. The welcome suggestions already gate on this;
  // the guaranteed row must too. It is the first thing a client installed without search would meet.
  let searchOffered = false;
  // The relevant marks as they stood when the last deep search completed, or null if none has. The press is
  // deterministic — the same description and the same marks put the same queries — so offering it again over
  // unchanged inputs invites the professional to pay for questions the enclave has already answered.
  // Henry, 25 Sep: "this recommendation is still showing right after i just did the deep search and changed
  // nothing". The extension already declined to suggest it; the page was adding it back unconditionally one
  // line below, which is the whole bug — each side was checked and the seam between them was not.
  let deepMarksAtLastPress = null;
  // Worded to match deepMarksKey() in ir-attested.ts. Order is not a change, so it sorts.
  const deepMarksKeyHere = () => relevantOrdered().slice().sort().join("\u0000");
  const IDEAS = [SURVEY,
                 "Search one feature of the disclosure on its own",
                 SUMMARISE_IDEA];
  const STEPS_MAX = 5;
  let assistantSteps = [];             // the suggestions that came with the latest answer
  let marksAtTurn = null;              // your marks when the assistant took up the current message

  function relevantOrdered() {
    const out = markOrder.filter((k) => marks.get(k) === "relevant");
    for (const k of Array.from(marks.keys())) if (marks.get(k) === "relevant" && !out.includes(k)) out.push(k);
    return out;                        // most recently marked first
  }
  // Candidate steps from marks — worded exactly as the extension words them (ir-attested.ts; a test checks).
  // `onlyNew`: from marks changed since the assistant took up the message, newest and most specific first.
  function markCandidates(onlyNew) {
    const isNew = (k) => !onlyNew || !marksAtTurn || marksAtTurn.get(k) !== marks.get(k);
    const relevant = relevantOrdered().filter(isNew);
    const excluded = Array.from(marks.keys()).some((k) => isNew(k) && (marks.get(k) === "known" || marks.get(k) === "not-relevant"));
    const like = relevant.slice(0, 2).map((k) => `Find documents like ${k}`);
    // "CONTINUE the survey" presupposes one. Marks belong to the MATTER and outlive a sitting, so a fresh
    // session opens holding every mark the professional ever made and was offering to continue a survey
    // that had not started — Henry, 25 Sep: "now im seeing this while the session is still fully empty".
    // The other mark steps are fine with nothing on screen: "find documents like US-X" is a new search,
    // not a continuation. This one is the only one whose words claim something about what has happened.
    const canContinue = excluded && cards.size > 0;
    if (onlyNew) return [...like.slice(0, 1), ...(relevant.length ? [DEEPER] : []), ...like.slice(1), ...(canContinue ? [LEAVE_OUT] : [])];
    return [...(relevant.length ? [DEEPER] : []), ...like, ...(canContinue ? [LEAVE_OUT] : [])];
  }
  // Does the assistant's list already offer this, perhaps in its own words? A publication number named anywhere
  // in it covers "find documents like" that document.
  function covered(step, list) {
    if (list.includes(step)) return true;
    const low = list.map((t) => t.toLowerCase());
    const like = /^Find documents like (\S+)$/.exec(step);
    if (like) return low.some((t) => t.includes(like[1].toLowerCase()));
    if (step === DEEPER) return low.some((t) => /\b(look|dig|go) deeper\b|\buse my marks\b|\bsteer\b/.test(t));
    if (step === LEAVE_OUT) return low.some((t) => /\bleav(e|ing) out\b|\bexclud|\bset(ting)? aside\b/.test(t));
    return false;
  }

  function renderSteps() {
    const bar = $("mark-steps");
    const list = $("mark-steps-list");
    clear(list);
    const started = $("empty").hidden;
    const groups = [];
    const mine = assistantSteps.slice(0, 4);
    if (mine.length) {
      groups.push({ title: "", steps: mine });
      const fresh = markCandidates(true).filter((st) => !covered(st, mine));
      const room = Math.max(1, STEPS_MAX - mine.length);
      if (fresh.length) groups.push({ title: "From marks you made since", steps: fresh.slice(0, room) });
    } else {
      const fromMarks = markCandidates(false);
      // A new session is its own sitting (Henry, 19 Sep): what earlier marks suggest is worth offering, but
      // until THIS session has run a search, running one comes first. Before the first message the welcome
      // already offers it.
      const survey = started && cards.size === 0 && fromMarks.length ? [SURVEY] : [];
      if (survey.length) groups.push({ title: "", steps: survey });
      if (fromMarks.length) groups.push({ title: "From your marks", steps: fromMarks.slice(0, STEPS_MAX - survey.length) });
      // Ideas wait for a conversation: before the first message the welcome's own suggestions are on screen,
      // and nothing presumes what has not happened — no summary before a search.
      else if (started) groups.push({ title: "Ideas", steps: IDEAS.filter((i) => i !== SUMMARISE_IDEA || cards.size > 0) });
    }
    // The deep search is offered on its own row and does not compete for the five places. It is the one
    // action the page guarantees is reachable: leaving it to the assistant to remember would make the
    // headline feature of this client appear or not depending on how an answer happened to end.
    // ...unless pressing it now would put exactly the queries the last press put. The page can see the marks
    // but NOT the disclosure text — nothing here reads the matter's files — so it decides the half it can,
    // and the tool itself refuses an identical press on the other half. Editing the description therefore
    // still leaves this hidden; the assistant can always be asked, and the tool will run it.
    const deepWouldRepeat = deepMarksAtLastPress !== null && deepMarksAtLastPress === deepMarksKeyHere();
    // After a press, the row asks for the follow-up rather than repeating the first press's own words.
    const deepStep = deepMarksAtLastPress === null ? DEEP : DEEP_FOCUSED;
    if (started && searchOffered && !deepWouldRepeat
        && !groups.some((g) => g.steps.includes(DEEP) || g.steps.includes(DEEP_FOCUSED))) {
      groups.push({ title: "", steps: [deepStep] });
    }
    // While the assistant works on a message, its steps for it are not written yet: an old list would be stale.
    if (!groups.length || busy || ended) { bar.hidden = true; return; }
    // In the conversation, right after the latest answer — part of what the assistant said, not page furniture
    // (Henry, 19 Sep: "maybe we should blend the buttons into the chat"). Re-appending moves it to the end.
    if (log.lastElementChild !== bar) {
      const keep = stick();
      log.append(bar);
      keep();
    }
    for (const g of groups) {
      if (g.title) list.append(el("div", "steps-sub", g.title));
      const row = el("div", "steps-row");
      for (const step of g.steps) {
        const b = el("button", (step === DEEP || step === DEEP_FOCUSED) ? "step-btn deep" : "step-btn", step);
        b.type = "button";
        b.addEventListener("click", () => send(step));
        row.append(b);
      }
      list.append(row);
    }
    bar.hidden = false;
  }
  // The names the rest of the page already calls.
  function renderMarkSteps() { renderSteps(); }       // declarations, not consts: callable from anywhere
  function renderNext() { renderSteps(); }
  // On sending: the steps belonged to the previous answer. Hidden at once — re-rendering here would briefly put
  // them back above the message being sent; the next answer brings its own.
  function clearNext() { assistantSteps = []; $("mark-steps").hidden = true; }

  function markButtons(keyNo, card, register = true) {
    const wrap = el("div", "marks");
    const opts = [["relevant", "Relevant"], ["not-relevant", "Not relevant"], ["known", "Known"],
                  // Taking the mark back off. Henry, 25 Sep: "there is no way to just remove the selection
                  // and not keep something selected". Whichever of the three you pressed first, the
                  // document stayed marked as SOMETHING, and "not relevant" is a judgement, not the
                  // absence of one — so there was no way to say "I have no opinion on this after all".
                  // Not a delete: the store is append-only because a changed mind is signal, so this
                  // appends a human row saying the opinion was withdrawn, and the record keeps both.
                  ["cleared", "Clear"]];
    const buttons = opts.map(([value, label]) => {
      const clearing = value === "cleared";
      const b = el("button", `m-${value}`, label);
      b.type = "button";
      b.setAttribute("aria-pressed", String(!clearing && marks.get(keyNo) === value));
      b.title = clearing
        ? `Remove your mark on ${keyNo} — the matter keeps that you made one and then took it off`
        : `Mark ${keyNo} as ${label.toLowerCase()} (your judgement, kept with the matter)`;
      // Nothing to clear when nothing is marked: an always-present Clear reads as a fourth judgement.
      if (clearing) b.hidden = !marks.get(keyNo);
      b.addEventListener("click", async () => {
        try {
          await api("/api/mark", { key: keyNo, mark: value });
          if (clearing) marks.delete(keyNo); else marks.set(keyNo, value);
          noteMarked(keyNo);
          refreshMarks(keyNo);
          renderMarkSteps();
          renderMarksPanel();
      renderResultsPanel();
          for (const e of cards.values()) if (e.keys && e.keys.includes(keyNo)) refreshCardSummary(e);
          toast(clearing ? `Cleared: ${keyNo} is no longer marked.`
                         : `Saved: ${keyNo} marked ${label.toLowerCase()}.`, "info");
          if (value === "relevant") offerDeeper(card);
        } catch (e) { toast(`Couldn't record the mark: ${e.message}`, "error"); }
      });
      wrap.append(b);
      return [value, b];
    });
    if (register) {
      if (!docRows.has(keyNo)) docRows.set(keyNo, []);
      docRows.get(keyNo).push(buttons);
    }
    return wrap;
  }
  // ── Your marks: every mark on this matter, in one place, and editable ─────────────────────────────
  //
  // Henry, 19 Sep: "maybe even we should have something to see which are set as relevant, or even the ones set
  // as not relevant, with a possibility to edit those". Marks belong to the MATTER, across sessions, but could
  // only be seen on a search card that happened to be on screen. Each row carries the same three buttons as a
  // card — changing a mark here updates the cards, the folded heads and the next steps, and the other way
  // round. What a document is about comes from every search recorded on the matter (/api/marks titles).
  // A mark can be changed, not removed: the matter keeps each mark's history, and the store takes no "none".
  const markTitles = new Map();          // publication number → title
  const MARK_GROUPS = [["relevant", "Relevant"], ["not-relevant", "Not relevant"], ["known", "Known"]];
  function renderMarksPanel() {
    const panel = $("marks-panel");
    const groups = $("marks-groups");
    clear(groups);
    const byValue = new Map(MARK_GROUPS.map(([v]) => [v, []]));
    for (const [k, v] of marks) if (byValue.has(v)) byValue.get(v).push(k);
    const total = Array.from(byValue.values()).reduce((t, l) => t + l.length, 0);
    panel.hidden = total === 0;
    if (!total) return;
    $("marks-count").textContent = MARK_GROUPS.map(([v, label]) => `${byValue.get(v).length} ${label.toLowerCase()}`)
      .filter((t) => !t.startsWith("0 ")).join(" · ");
    for (const [v, label] of MARK_GROUPS) {
      const keys = byValue.get(v).sort();
      if (!keys.length) continue;
      const list = el("ul", "marks-list");
      for (const k of keys) {
        const title = markTitles.get(k) || docTitleOnPage(k) || "";
        const row = el("li", "mark-row", el("div", "mark-doc", el("span", "key", k), title ? el("span", "mark-title", title) : null),
          markButtons(k, null, false));
        list.append(row);
      }
      groups.append(el("div", "marks-group", el("div", "steps-sub", `${label} (${keys.length})`), list));
    }
  }
  // EVERY document the searches on screen returned, most relevant first, each one clickable. It appears only
  // once a DEEP search has completed, because that is the point at which the list is worth reading rather than
  // a restatement of one card. Henry, 30 Sep: "a second tab that appears when a deep search was done, with the
  // relevance sorted list of patents that can be clicked as well for opening".
  //
  // The ordering is stated in the panel rather than implied. A document's position is the BEST rank it reached
  // in any single search (rank 1 in one search beats rank 4 in three), tie-broken by how many searches returned
  // it. The search machine signs a per-search order; it does not sign a combined one, so presenting this as a
  // relevance SCORE would be inventing a number nothing attests.
  function renderResultsPanel() {
    const panel = $("results-panel");
    if (!panel) return;
    const best = new Map();              // key → {rank, seen, title}
    for (const e of cards.values()) {
      const keys = e.keys || [];
      keys.forEach((k, i) => {
        if (!k) return;
        const prev = best.get(k);
        const title = (e.titles && e.titles.get(k)) || (prev && prev.title) || "";
        if (!prev) best.set(k, { rank: i + 1, seen: 1, title });
        else { prev.rank = Math.min(prev.rank, i + 1); prev.seen += 1; if (!prev.title) prev.title = title; }
      });
    }
    // Hidden only while there is nothing to list. It WAS gated on a deep search having completed, from a
    // literal reading of "a second tab that appears when a deep search was done" — which made it invisible
    // after an ordinary search and read as not built at all (Henry, 2026-09-30: "did you implement...").
    // The list is worth reading as soon as any search has returned documents.
    panel.hidden = best.size === 0;
    if (panel.hidden) return;
    const rows = Array.from(best.entries())
      .sort((a, b) => a[1].rank - b[1].rank || b[1].seen - a[1].seen || a[0].localeCompare(b[0]));
    $("results-count").textContent = `${rows.length} document${rows.length === 1 ? "" : "s"} across `
      + `${cards.size} search${cards.size === 1 ? "" : "es"}`;
    const list = el("ol", "results-list-ol");
    for (const [k, info] of rows) {
      const meta = info.seen > 1 ? el("span", "year", `in ${info.seen} searches`) : null;
      list.append(el("li", "result-row",
        el("div", "mark-doc", docLink(k), meta, info.title ? el("span", "mark-title", info.title) : null),
        markButtons(k, null, false)));
    }
    const holder = $("results-list");
    clear(holder);
    holder.append(list);
  }

  // A title from a search card on this page, for a document marked in this session.
  function docTitleOnPage(k) {
    for (const e of cards.values()) if (e.titles && e.titles.has(k)) return e.titles.get(k);
    return "";
  }


  // ── documents you've opened ─────────────────────────────────────────────────────────────────────
  //
  // Henry, 2026-10-01: "im not seeing any popup or list of opened patents we can come back to". Two
  // documents he had opened were buried in a 2,774-event transcript with no way back to them.
  //
  // The list comes from the RECORDED ARCHIVE, not from this page's memory, which is what makes it worth
  // having: it holds documents opened in earlier sessions on this matter, it survives a reload, and showing
  // one again spends no sealed request because the text is already on this computer.
  let docsCache = { documents: [], readings: {} };

  async function refreshDocuments() {
    let got;
    try {
      got = await api("/api/documents");
    } catch {
      return;                                     // a list that cannot load must not break the session
    }
    docsCache = { documents: got.documents || [], readings: got.readings || {} };
    const panel = $("docs-panel");
    const list = $("docs-list");
    list.textContent = "";
    if (!docsCache.documents.length) { panel.hidden = true; return; }
    for (const d of docsCache.documents) {
      const b = el("button", "", el("span", "dkey", d.key + (yearOf(d) ? ` (${yearOf(d)})` : "")));
      b.append(el("span", "dtitle", titleOf(d)));
      b.type = "button";
      b.addEventListener("click", () => showDocument(d.key));
      list.append(el("li", "", b));
    }
    $("docs-note").textContent = docsCache.documents.length === 1
      ? "Opening it again costs nothing — it is read from this computer."
      : "Opening one again costs nothing — they are read from this computer.";
    panel.hidden = false;
  }

  function yearOf(d) {
    const p = String(d.published ?? "");
    return /^\d{8}$/.test(p) ? p.slice(0, 4) : "";
  }

  // The corpus is "Title. Abstract", so the first sentence is the title.
  function titleOf(d) {
    const t = String(d.text || "").replace(/\s+/g, " ").trim();
    const stop = t.indexOf(". ");
    return (stop > 0 ? t.slice(0, stop) : t).slice(0, 140);
  }

  const COVER_WORDS = { held: "in full", truncated: "truncated", claim_1: "first claim only", not_held: "not in this index" };

  function showDocument(key) {
    const d = docsCache.documents.find((x) => x.key === key);
    if (!d) return;
    $("docview-title").textContent = `${d.key}${yearOf(d) ? ` · published ${yearOf(d)}` : ""}`;
    // JUDGE IT WHERE YOU READ IT. Reading a document is exactly when an opinion forms, and the controls were
    // a panel away — Henry, 2026-10-01: "that popup view should include the relevant, non relevant selectors".
    // markButtons() is the card's own builder, so a mark made here shows on every card, the folded heads, the
    // marks panel and the next steps at once, and no second opinion about what this document is marked can
    // exist. register=false: this row is rebuilt each time the popup opens, so it must not accumulate in the
    // registry that refreshMarks() walks.
    const marksBox = $("docview-marks");
    clear(marksBox);
    marksBox.append(markButtons(d.key, null, false));
    // WHAT WAS READ AND WHAT WAS NOT, before the text — the same order the assistant is given it in, and for
    // the same reason: a reader handed a short text without its scope takes it for the document.
    const cov = d.coverage || {};
    const parts = ["abstract", "claims", "description"]
      .filter((k) => cov[k] !== undefined)
      .map((k) => `${k} ${COVER_WORDS[cov[k]] || cov[k]}`);
    const absent = ["claims", "description"].filter((k) => cov[k] === "not_held");
    $("docview-scope").textContent = parts.length
      ? `What the sealed index holds: ${parts.join(" · ")}.`
        + (absent.length ? ` The ${absent.join(" and ")} ${absent.length > 1 ? "were" : "was"} not read — nothing here describes ${absent.length > 1 ? "them" : "it"}.` : "")
      : "";
    $("docview-text").textContent = String(d.text || "");
    const said = $("docview-said");
    said.textContent = "";
    const reading = docsCache.readings[d.key];
    if (reading) {
      said.append(el("p", "sub", "What the assistant said about it in this session:"));
      // markdown(), the same renderer the conversation uses. Printing the raw source put "**bold**",
      // "> *quote*" and "- item" on screen as literal characters in a single unbroken wall — Henry,
      // 2026-10-01: "the assistant side formatting could be made more readable". The assistant writes
      // markdown because the log renders it; a second surface showing the same text must render it too,
      // or the page is asking the reader to parse what it chose not to.
      said.append(markdown(reading));
    } else {
      said.append(el("p", "sub",
        "The assistant has not written about this document yet. Ask it about this number and its answer appears here."));
    }
    const prov = [];
    if (d.index) prov.push(`index ${d.index}`);
    if (d.measurement) prov.push(`sealed machine ${String(d.measurement).slice(0, 12)}…`);
    if (d.at) prov.push(`read ${d.at}`);
    $("docview-prov").textContent = prov.join(" · ");
    $("docview").hidden = false;
  }

  function hideDocument() { $("docview").hidden = true; }
  $("docview-close").addEventListener("click", hideDocument);
  $("docview").addEventListener("click", (e) => { if (e.target === $("docview")) hideDocument(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("docview").hidden) hideDocument(); });

  function refreshMarks(keyNo) {
    const now = marks.get(keyNo);
    for (const group of docRows.get(keyNo) || []) {
      for (const [value, b] of group) {
        // Clear is an action on an existing mark, never a fourth judgement: it is never "pressed", and it
        // is absent while there is nothing to clear. Every row for this document is updated, so the same
        // document in two cards and in the marks panel never disagrees about what it is marked.
        if (value === "cleared") { b.setAttribute("aria-pressed", "false"); b.hidden = !now; continue; }
        b.setAttribute("aria-pressed", String(now === value));
      }
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
    const n = entry.n;
    const fresh = entry.fresh === undefined ? n : entry.fresh;
    entry.sub.textContent = `${n} document${n === 1 ? "" : "s"}${fresh < n ? ` · ${fresh} new` : ""}`;
    // How these results overlap the earlier searches, named by what those searches were about; the two
    // largest overlaps in words, the rest counted. Then your marking, which a fold must never hide.
    const notes = [];
    const overlap = Array.from((entry.overlap || new Map()).entries()).sort((x, y) => y[1] - x[1]);
    for (const [no, c] of overlap.slice(0, 2)) notes.push(`${c} also in ${shortAbout(no)}`);
    if (overlap.length > 2) {
      const more = overlap.slice(2).reduce((t, [, c]) => t + c, 0);
      notes.push(`${more} in ${overlap.length - 2} other search${overlap.length - 2 === 1 ? "" : "es"}`);
    }
    if (marked) notes.push(`${marked} marked${relevant ? `, ${relevant} relevant` : ""}`);
    if (entry.notes) { entry.notes.textContent = notes.join(" · "); entry.notes.hidden = !notes.length; }
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
      // ...and anything folded INSIDE the card it lives in. A deep survey's legs fold on their own.
      if (item.open) item.open();
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
    // A REPEAT of the current phase is a heartbeat, not a transition. The clock for "slower than usual"
    // runs from when the step began, so restarting it on every heartbeat would hide exactly the slow
    // search the indicator exists to show — a liveness signal must not overwrite a duration.
    const same = entry.phase === phase;
    if (entry.phase === "approval" && !same) entry.approvalMs += when - entry.phaseAt;
    entry.phase = phase;
    if (!same) entry.phaseAt = when;
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
  function shortAbout(no, max = 42) {
    const e = searchesByNo.get(no);
    const about = e && e.about ? e.about : "";
    if (!about) return `search ${no}`;
    return `‘${about.length > max ? `${about.slice(0, max - 1).trimEnd()}…` : about}’`;
  }
  // Where the press did NOT reach, said plainly, from facts the record already holds. This is the
  // deliberate alternative to a second autonomous turn: ruled with sealed-research on 24 Sep, an adaptive
  // turn is gated on counsel AND on a change in the shape of the approval — a press-time approval cannot
  // cover queries that do not exist yet. Reporting the gap makes the professional the second turn, so no
  // query is ever sent that they could not see coming.
  function deepCoverage(d) {
    const legs = d.legs || [];
    const empty = legs.filter((l) => l.status === "empty");
    // "Added nothing new", NOT "one family": collapsing siblings needs the family map, which lives on the
    // search side. Guessing family from publication numbers misses the cross-jurisdiction siblings that are
    // most of the duplication, so claim the weaker thing that is actually computed.
    const spent = legs.filter((l) => l.status === "ok" && l.added === 0);
    if (!empty.length && !spent.length) return null;
    const box = el("div", "deep-coverage");
    if (empty.length) {
      box.append(el("div", "", `${empty.length} ${empty.length === 1 ? "query" : "queries"} found nothing: `
        + empty.map((l) => l.feature).join("; ") + "."));
    }
    if (spent.length) {
      box.append(el("div", "", `${spent.length} found only documents the other queries had already returned: `
        + spent.map((l) => l.feature).join("; ")
        + " — that part of the description is covered by what you already have, not unsearched."));
    }
    box.append(el("div", "sub", "Marking a document relevant makes the next deep search walk outward from "
      + "it, so pressing again after marking searches differently rather than repeating this."));
    return box;
  }

  function seenIn(no) {
    const e = searchesByNo.get(no);
    const tag = el("span", "seen", `also in ${shortAbout(no)}`);
    if (e && e.about) tag.title = `Also returned by search ${no}: ${e.about}`;
    return tag;
  }

  function toolStart(ev) {
    hideWelcome();
    const s = stick();
    if (ev.tool === "suggest_next_steps") {
      return;
    }
    if (ev.tool === "deep_prior_art_search") {
      // One press, several sealed searches. Built like a search card and NOT a special case: it folds, it
      // is keyed the way the bridge keys events, and it goes in the outline. The first version keyed it on
      // `ev.toolCallId`, which the bridge does not send — so the card was stored under `undefined`, never
      // found again, and sat on "planning the queries…" while six queries ran and finished behind it.
      const a = ev.args || {};
      const card = el("div", "card");
      const sub = el("span", "sub", "planning the queries…");
      const title = el("span", "title", "🔍 Deep prior-art survey");
      const qline = String(a.text || "").replace(/\s+/g, " ").trim();
      const what = el("span", "what", `“${qline.length > 110 ? `${qline.slice(0, 109).trimEnd()}…` : qline}”`);
      const notes = el("span", "notes", "");
      notes.hidden = true;
      const toggle = el("button", "card-toggle", "▾");
      toggle.type = "button";
      toggle.setAttribute("aria-expanded", "true");
      toggle.setAttribute("aria-label", "Collapse this survey");
      const head = el("div", "card-head", toggle, title, what, sub, notes);
      card.append(head);
      const body = el("div", "card-body");
      if (qline) body.append(el("div", "card-query", qline.length > 320 ? `${qline.slice(0, 320)}…` : qline));
      card.append(body);
      const t0 = ev.at || serverNow();
      const entry = { card, sub, title, body, toggle, head, notes, keys: [], collapsed: false, byUser: false,
                      startedAt: t0, phase: "verifying", phaseAt: t0, approvalMs: 0, done: false, deep: true };
      const flip = (e) => { if (e) e.stopPropagation(); setCollapsed(entry, !entry.collapsed, true); };
      toggle.addEventListener("click", flip);
      head.addEventListener("click", (e) => {
        const sel = window.getSelection && window.getSelection();
        if (sel && !sel.isCollapsed && head.contains(sel.anchorNode)) return;
        flip(e);
      });
      autoCollapse();
      log.append(card);
      cards.set(ev.call, entry);
      setCollapsed(entry, true);
      entry.about = "deep survey";
      outlineAdd({ kind: "search", el: card, label: "Deep survey",
                   detail: qline.slice(0, 60), entry });
      return;
    }
    if (ev.tool === "prior_art_search") {
      const a = ev.args || {};
      const card = el("div", "card");
      const sub = el("span", "sub", "checking the search machine…");
      const title = el("span", "title", "🔍 Sealed patent search");
      // The head is what you read, since a card now starts folded: it always says what was searched — a search
      // with no feature name used to show nothing here — and has a line of notes for the results.
      const qline = String(a.text || "").replace(/\s+/g, " ").trim();
      const what = el("span", "what", a.feature ? `feature: ${a.feature}`
        : a.like ? `documents like ${String(a.like).toUpperCase()}`
        : `“${qline.length > 110 ? `${qline.slice(0, 109).trimEnd()}…` : qline}”`);
      const notes = el("span", "notes", "");
      notes.hidden = true;
      // A real button carries the state for a screen reader and the keyboard; the whole head is also a
      // click target, because a 12px chevron is not one.
      const toggle = el("button", "card-toggle", "▾");
      toggle.type = "button";
      toggle.setAttribute("aria-expanded", "true");
      toggle.setAttribute("aria-label", "Collapse this search");
      const head = el("div", "card-head", toggle, title, what, sub, notes);
      card.append(head);
      const body = el("div", "card-body");
      const q = String(a.text || "");
      if (q) body.append(el("div", "card-query", q.length > 320 ? `${q.slice(0, 320)}…` : q));
      card.append(body);
      // Timed from the SERVER's stamp on the event: a reload replays history, and a clock started on receipt
      // would restart every running search at zero.
      const t0 = ev.at || serverNow();
      const entry = { card, sub, title, body, toggle, head, notes, keys: [], collapsed: false, byUser: false,
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
      // Folded from the start (Henry, 19 Sep: "by default, could you not even expand the search results frames,
      // just update within the compacted view what needs to be"). The head carries the progress, what was
      // searched, the counts and how the results overlap earlier searches; you open a card to read or mark its
      // documents. Two exceptions stand: a refusal opens itself, and a card you opened stays open.
      autoCollapse();
      log.append(card);
      cards.set(ev.call, entry);
      setCollapsed(entry, true);
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

  // A CONNECTION failure must not be shown as a VERIFICATION failure. Henry, 30 Sep: a reaped test
  // enclave produced "the search enclave did not verify (… no valid offer (URLError))" — a trust verdict
  // about a machine that was not there. The composed text still carries the "did not verify" prefix, so
  // these branches REPLACE it rather than appending to it; the raw text stays one click away as detail.
  //
  // Ordering matters: "nothing answered" is checked BEFORE the verification branch, because the composed
  // string contains both and the first match wins. The verifier now says which of the two happened.
  function plainRefusal(text) {
    const t = String(text || "").toLowerCase();
    if (t.includes("declined")) return "You didn't allow this search, so nothing was sent.";
    if (t.includes("nothing answered") || t.includes("no connection"))
      return "The search machine isn't running, so nothing was sent. Nothing about your text left this computer.";
    if (t.includes("did not answer") || t.includes("unreachable") || t.includes("timed out"))
      return "The search machine isn't answering, so nothing was sent. It may not be running right now.";
    // Something WAS listening and its answer was not a usable offer — that is trust-relevant, and the
    // wording says so rather than blaming the connection.
    if (t.includes("not with an offer") || t.includes("not with a usable offer"))
      return "Something answered at that address but it is not a sealed search machine, so nothing was sent.";
    if (t.includes("did not verify"))
      return "The search machine could not be verified, so nothing was sent.";
    return `The search was not sent: ${text}`;
  }

  // Parallel requests slip together: one line with a count, not a column of identical lines (19 Sep: ten in a
  // row). A card's slip joins a slip line in the same run of search cards, looking both ways: parallel searches
  // each put their card in first and their answers come back in any order, so the slip line can sit several
  // cards away. The run ends at anything that is not a card or a slip — a message is a new moment.
  function recordSlip(card) {
    const inRun = (n) => n && n.classList && (n.classList.contains("card") || n.classList.contains("slip"));
    let near = null;
    for (const step of ["previousElementSibling", "nextElementSibling"]) {
      for (let n = card[step]; !near && inRun(n); n = n[step]) if (n.classList.contains("slip")) near = n;
    }
    if (near) {
      near.slipCount = (near.slipCount || 1) + 1;
      near.querySelector(".slip-count").textContent = ` (${near.slipCount} requests)`;
      card.remove();
      return near;
    }
    const line = el("div", "step slip", el("span", "step-dot", "·"),
      el("span", "", "The assistant's search request was malformed, so nothing was sent."), el("span", "slip-count", ""));
    card.replaceWith(line);
    return line;
  }

  function toolEnd(ev) {
    toolRunning = "";
    updateActivity();
    if (ev.tool === "suggest_next_steps") {
      const steps = ev.ok && ev.details && Array.isArray(ev.details.steps) ? ev.details.steps : [];
      assistantSteps = steps.map(String).filter((t) => t && !/^[\/!]/.test(t)).slice(0, 4);
      renderSteps();
      return;
    }
    if (ev.tool === "deep_prior_art_search") {
      const e = cards.get(ev.call);
      if (!e) return;
      e.done = true;
      e.sub.classList.remove("slow");
      const d = ev.details || {};
      // Remember what this press was made from, so the guaranteed row below stops offering a press that
      // would put the same queries. A press that FAILED, or that the tool refused as an identical repeat,
      // must not arm this: the first did not cover these marks, and the second did not happen at all.
      if (ev.ok && !d.repeat && d.sent) deepMarksAtLastPress = deepMarksKeyHere();
      renderResultsPanel();        // the deep search just finished: the list is now worth showing
      const keep = stick();
      // The head carries what you read while it is FOLDED; the body carries what you open it for. Putting
      // the whole result in `sub` — which lives in the head — meant a folded card either said nothing or
      // spilled the lot into its own title bar.
      if (!ev.ok) {
        e.sub.textContent = "the survey did not complete";
        e.sub.classList.add("warn");
        clear(e.body);
        e.body.append(el("div", "warn", String(ev.text || "the deep survey did not complete")));
        setCollapsed(e, false, false);          // a refusal opens itself, as a search's does
      } else {
        e.sub.textContent = "";
        e.notes.hidden = false;
        e.notes.textContent = `${d.sent}/${d.planned} queries · ${d.documents} documents`;
        // WHICH ROUND. A second press that looks identical to the first is how an autonomous survey reads
        // as a repeat; the round, and the reason the assistant gave for it, are what make it legible.
        e.title.textContent = d.generation > 1
          ? `🔍 Deep prior-art survey · round ${d.generation} of ${d.of || d.generation}`
          : `🔍 Deep prior-art survey`;
        clear(e.body);
        // `.card-body` carries no padding of its own — in an ordinary search card every child brings its
        // own (`.card-query`, `.doc`, `.card-foot`). Bare divs appended here sat flush against the border.
        e.body.append(el("div", "deep-summary",
          el("div", "", `${d.sent} of ${d.planned} sealed queries completed — ${d.documents} distinct documents.`),
          // WHY it was this size: the count alone reads as the search having given up, and the reasons are
          // the part the professional can act on.
          el("div", "sub", `It put ${d.planned} of a possible ${d.cap}. ${(d.notes || []).join("; ")}.`),
          // The assistant's own reason for a composed round, shown to the professional rather than kept in
          // the record: these are the queries nobody read before they were sent, so the one thing owed is
          // an account of why they were.
          d.because ? el("div", "deep-because", `Why this round: ${d.because}`) : null,
          deepCoverage(d)));
        for (const leg of d.legs || []) {
          const mark = leg.status === "ok" ? "·" : leg.status === "empty" ? "–" : "✗";
          // A leg that returns ten documents the other legs already returned looks like the strongest leg
          // in the press when only the hit count is shown. What it ADDED is the number that says whether
          // this part of the description was reached by anything else.
          const added = leg.added;
          const contributed = typeof added === "number"
            ? (added === 0 ? ", none new" : ` (${added} new)`) : "";
          const count = leg.status === "ok" ? `${leg.hits} document(s)${contributed}`
            : leg.status === "empty" ? "nothing returned" : (leg.why || "did not complete");
          // A press puts up to eight searches, each with ten documents and its own marking controls. Opened
          // all at once that is most of a screen per leg and the SHAPE of the survey — which parts of the
          // description were reached, and by what — is somewhere inside it. So a leg folds, and starts
          // folded: the card opens as a readable list of what was put, and a leg opens when it is asked
          // for. Henry, 25 Sep: "they should stay collapsed in the beginning and only expand when clicked".
          const block = el("div", `deep-leg ${leg.status} folded`);
          const legBody = el("div", "deep-leg-body");
          const head = el("button", "deep-leg-head",
            `${mark} ${leg.searchNo ? `Search ${leg.searchNo} · ` : ""}${leg.feature} — ${count}`);
          head.type = "button";
          head.setAttribute("aria-expanded", "false");
          const setLeg = (open) => {
            block.classList.toggle("folded", !open);
            head.setAttribute("aria-expanded", String(open));
          };
          head.addEventListener("click", () => setLeg(block.classList.contains("folded")));
          block.append(head, legBody);
          if (leg.about) legBody.append(el("div", "deep-leg-about", `“${leg.about}”`));
          // A leg IS an ordinary sealed search, so it gets what one gets: its documents, and the controls
          // to mark them. Listing a count and calling that a trace gave the outline nowhere to arrive.
          const docs = leg.docs || [];
          if (docs.length) {
            const list = el("ol", "docs");
            const [_llo, _lhi] = scoreRange(docs);
            docs.forEach((doc, idx) => {
              const keyNo = String(doc.key || "");
              const title = el("div", "dtitle", String(doc.title || ""));
              const row = el("li", "doc",
                el("span", "rank", String(idx + 1)),
                relBar(doc.score, _llo, _lhi),
                el("div", "", docLink(keyNo), doc.year ? el("span", "year", String(doc.year)) : null,
                  doc.alsoIn ? seenIn(doc.alsoIn) : null, title),
                markButtons(keyNo, e.card));
              title.addEventListener("click", () => row.classList.toggle("open"));
              list.append(row);
            });
            legBody.append(list);
          }
          e.body.append(block);
          // The outline points at THIS leg, not at the card: being sent to the top of a six-search card is
          // not arriving at search 5.
          if (leg.about) {
            // The outline must OPEN the leg, not only scroll to it. Being sent to a folded block is the
            // same nothing-happened as being sent to a folded card, which this already handles one level
            // up — and Henry reported exactly that symptom on 24 Sep, before legs could fold at all.
            outlineAdd({ kind: "search", el: block, entry: e, open: () => setLeg(true),
                         label: leg.searchNo ? `Search ${leg.searchNo}` : "Search",
                         detail: `${leg.about.slice(0, 54)}${leg.about.length > 54 ? "…" : ""}` });
          }
        }
        e.body.append(el("div", "card-foot", "These are the combined results of separate queries, not a "
          + "merged ranking: the same invention can appear more than once under different publication "
          + "numbers. Mark what matters — the next deep search walks outward from what you marked."));
      }
      // The guaranteed deep row is decided from what the last press was made from, which has just changed.
      // Without this the flag moves and nothing repaints: the row would keep offering a repeat until some
      // unrelated event happened to redraw it, which is how this looked correct in the code and wrong on
      // the screen.
      renderSteps();
      keep();
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
    const slip = /needs a self-contained description|was not returned by (a|any) search|Validation failed for tool/.test(String(ev.text || ""));
    if (!ev.ok && slip) {
      recordSlip(card);
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
    entry.fresh = docs.length - again;
    entry.overlap = new Map();                       // earlier search number → how many of these it returned too
    for (const doc of docs) if (doc.alsoIn) entry.overlap.set(doc.alsoIn, (entry.overlap.get(doc.alsoIn) || 0) + 1);
    if (d.testRoots) body.append(el("div", "card-note warn", "TEST machine: checked against test keys, not a real verification."));
    else body.append(el("div", "card-note", `🔒 ${d.ours ? "InferRoute's sealed search machine" : "Sealed search machine"}, checked just before the search. Only that machine could read the query.`));
    const list = el("ol", "docs");
    const [_lo, _hi] = scoreRange(docs);
    docs.forEach((doc, idx) => {
      const keyNo = String(doc.key || "");
      const title = el("div", "dtitle", String(doc.title || ""));
      const keyEl = docLink(keyNo);
      const row = el("li", "doc",
        el("span", "rank", String(idx + 1)),
        relBar(doc.score, _lo, _hi),
        el("div", "", keyEl, doc.year ? el("span", "year", String(doc.year)) : null,
          doc.alsoIn ? seenIn(doc.alsoIn) : null, title),
        markButtons(keyNo, card));
      title.addEventListener("click", () => row.classList.toggle("open"));
      list.append(row);
    });
    body.append(list);
    body.append(el("div", "card-foot", "Mark what matters: saved as you click, kept with the matter. The assistant can read your marks to steer its next searches, but can't make or change them. A search finds related documents; it doesn't prove novelty. The bar shows how strongly each one matched RELATIVE TO THE OTHERS IN THIS SEARCH — a search returns the best it found, not only the ones worth reading, so a short bar means this one was among the weakest here, not that it is irrelevant."));
    if (docs.some((d) => marks.get(String(d.key)) === "relevant")) offerDeeper(card);
    entry.keys = docs.map((doc) => String(doc.key || ""));
    entry.titles = new Map(docs.map((doc) => [String(doc.key || ""), String(doc.title || "")]));
    entry.n = docs.length;
    renderResultsPanel();                // a search's documents just landed; the panel is keyed off cards
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
        // What the assistant is shown of your marks is fixed when it takes up your message; marks after that
        // are ones it has not seen.
        if (busy) marksAtTurn = new Map(marks);
        updateActivity();
        renderSteps();
        break;
      case "stall": showStalled(ev.value === true, ev.seconds); break;
      case "conversation_kept": $("kept-note").hidden = false; break;
      case "assistant_start": assistantStart(); break;
      case "assistant_delta": assistantDelta(ev.text); break;
      case "assistant_end":
        assistantEnd(ev);
        // The assistant's words about a document are attached when the turn ends, so a popup opened after
        // this shows them instead of "has not written about this document yet".
        if (docsCache.documents.length) refreshDocuments();
        break;
      case "tool_start": toolStart(ev); break;
      case "tool_end":
        toolEnd(ev);
        // A read just landed: the archive has it now, so the list can show it.
        if (ev.tool === "read_patent") refreshDocuments();
        break;
      case "tool_progress": {
        const e = cards.get(ev.call);
        // A survey's position, so a press that runs for minutes shows movement rather than the same three
        // phase names. The page composes the words; only integers crossed.
        if (e && e.deep && Number.isInteger(ev.steps) && Number.isInteger(ev.step)) {
          e.step = ev.step;
          e.steps = ev.steps;
          if (!e.done) e.sub.textContent = `search ${ev.step} of ${ev.steps} — ${PHASE_TEXT[ev.phase] || "working"}…`;
        }
        setPhase(e, ev.phase, ev.at);
        break;
      }
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
    searchOffered = Boolean(s.search);
    $("layout").hidden = false;
    document.title = `Probant · ${s.matter}`;
    $("matter").textContent = String(s.matter || "").replace("/", " / ");
    if (s.date_bound) { $("bound").textContent = s.date_bound; $("bound-wrap").hidden = false; }
    renderTrust(s.trust);
    // Documents opened in EARLIER sessions on this matter, present from the first paint. That is the point of
    // reading them from the archive rather than from this page's own history.
    refreshDocuments();
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
      for (const [k, t] of Object.entries(m.titles || {})) markTitles.set(k, t);
      renderMarksPanel();
      renderResultsPanel();
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
    finally { b.disabled = false; b.textContent = "Check the machines again"; }
  });
  // A second opinion that is not ours: the professional's own AI audits an evidence-only copy — the machines,
  // the signatures and the identity, with none of the invention's words. Their Claude subscription, or the
  // generic `ir` agent when they have none.
  function copyButton(text, label) {
    const b = el("button", "small", label || "Copy");
    b.type = "button";
    b.addEventListener("click", () => navigator.clipboard.writeText(text).then(() => toast("Copied.", "info")).catch(() => {}));
    return b;
  }
  function auditOffer(box) {
    clear(box);
    box.className = "audit-offer";        // its own block: the panel's container carries no styling of its own
    const go = el("button", "ghost", "Have your own AI audit it");
    go.type = "button";
    box.append(el("div", "audit-title", "A second opinion that isn't ours"),
      el("p", "sub", "Your own AI checks this proof against a brief, on an evidence-only copy: the hardware "
        + "reports, signatures and identity, with none of your client's words (no queries, results or document "
        + "text). It takes ten to fifteen minutes and needs no account with us."), go);
    go.addEventListener("click", async () => {
      go.disabled = true;
      go.textContent = "Preparing the audit pack…";
      try {
        const r = await api("/api/audit-pack", {});
        clear(box);
        box.className = "audit-offer ready";
        // A launch button rather than a command to copy: the pack is ready, the folder is known, and asking
        // someone to copy a line, find a terminal and paste it is three steps between them and the second
        // opinion this whole panel exists to get. The command stays on screen — it is what they are being
        // asked to trust — and copying stays available where there is no terminal to open.
        const launch = (agent, label) => {
          const b = el("button", "small primary", label);
          b.type = "button";
          b.addEventListener("click", async () => {
            b.disabled = true;
            const was = b.textContent;
            b.textContent = "Opening a terminal…";
            try {
              const got = await api("/api/audit-launch", { agent });
              toast(`Opened in ${got.terminal}. The audit runs there and keeps going if you close this page.`, "info");
              b.textContent = "Opened";
            } catch (e) {
              b.disabled = false;
              b.textContent = was;
              toast(e.message, "error");
            }
          });
          return b;
        };
        const offer = (agent, cmd) => (r.can_launch
          ? [el("span", "mono", cmd), el("div", "row", launch(agent, "Run it in a terminal"),
                                          copyButton(`cd "${r.path}" && ${cmd}`, "Copy instead"))]
          : [el("span", "mono", cmd), copyButton(`cd "${r.path}" && ${cmd}`, "Copy (goes to the folder too)")]);
        box.append(el("div", "audit-title", "Audit pack ready"),
          el("span", "mono", r.path),
          el("p", "", el("b", "", "With your Claude subscription"), r.can_launch ? ":" : ", in that folder run:"),
          ...offer("claude", r.claude),
          el("p", "", el("b", "", "No Claude subscription?"), " Use your InferRoute account instead:"),
          ...offer("ir", r.ir),
          el("p", "sub", "The brief (AUDIT.md) asks for a verdict on each claim and has it redo the key checks with "
            + "its own tools, not only run ours. It takes ten to fifteen minutes — let it finish. Two checks need "
            + "your client's words, so it will report those as not checked; the check on this computer covers them."));
      } catch (e) { go.disabled = false; go.textContent = "Have your own AI audit it"; toast(e.message, "error"); }
    });
    return box;
  }

  // Proof, not only our word: the record is exported and checked by its own verifier — the same file anyone
  // else would run — and the answer shows here, in the five questions a professional has.
  $("export").addEventListener("click", async () => {
    const b = $("export");
    b.disabled = true;
    b.textContent = "Exporting and checking…";
    const out = $("export-result");
    clear(out);
    out.hidden = false;
    out.append(el("p", "sub", "Writing the signed record, then running its own verifier. This takes a few seconds."));
    try {
      const r = await api("/api/prove", {});
      const copy = el("button", "small", "Copy folder path");
      copy.type = "button";
      copy.addEventListener("click", () => navigator.clipboard.writeText(r.path).then(() => toast("Copied.", "info")).catch(() => {}));
      const verdict = el("div", "check-result");
      renderCheck(verdict, r.check || {}, true);
      clear(out);
      out.append(verdict,
        el("div", "export-where", el("b", "", "The record"), " holds the disclosure in plain text: store it like the client file. Open record.html in:"),
        el("span", "mono", r.path), copy);
    } catch (e) { clear(out); out.hidden = true; toast(e.message, "error"); }
    finally { b.disabled = false; b.textContent = "Export and check the record"; }
  });
  $("end").addEventListener("click", () => {
    if (!window.confirm("End this session? The assistant stops; your marks and records stay with the matter.")) return;
    endSession($("end"));
  });

  init();
})();
