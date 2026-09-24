/**
 * ir attested session for Pi.
 *
 * Shows the user what this machine verified, in Pi's own UI, for both remote legs:
 *  - the model enclave: a footer status and a proof card, read from ir's local sealed endpoint;
 *  - the search enclave: a footer status and a proof card per search, read from the local search verifier.
 * Verification text is never produced by the model and never sent to it: proof cards are custom entries
 * or tool `details`, which Pi keeps out of model context.
 *
 * Refuses a model request unless the model session is verified and addressed to this session's local
 * endpoint. `prior_art_search` verifies the search enclave, asks the user before the first sealed query to
 * that enclave, and fails on any refused check. Tools outside the launch allowlist are refused.
 */
import type { ExtensionAPI, ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import { Box, Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ENDPOINT = (process.env.IR_ATTESTED_ENDPOINT ?? "").replace(/\/+$/, "");
const SEARCH = (process.env.IR_SEARCH_ENDPOINT ?? "").replace(/\/+$/, "");
// The sealed endpoint belongs to one session and checks a credential; this is that session's key.
const ENDPOINT_KEY = process.env.IR_ATTESTED_KEY ?? "";
const PROVIDER = process.env.IR_ATTESTED_PROVIDER ?? "inferroute";
const TOOLS = new Set((process.env.IR_ATTESTED_TOOLS ?? "").split(",").map((t) => t.trim()).filter(Boolean));
const STATUS_KEY = "ir-model-enclave";
const SEARCH_STATUS_KEY = "ir-search-enclave";
const LIFECYCLE_STATUS_KEY = "ir-enclave-lifecycle";
const PROOF_ENTRY = "ir-attested-proof";
const SEARCH_PROOF_ENTRY = "ir-search-proof";
const REFRESH_MS = 30_000;
const MATTER = process.env.IR_REPORT_MATTER ?? "";
const SEARCH_TIMEOUT_MS = 300_000;

// ───────────────────────── model enclave ─────────────────────────

interface ReceiptCheck {
	ok?: boolean;
	why?: string;
	label?: string;
}

interface Receipt {
	verdict?: string;
	refusal?: string;
	model_short?: string;
	verified_at?: string;
	started_at?: string;
	transport?: string;
	path?: string;
	instance?: { id?: string; gpu_count?: number };
	checks?: Record<string, ReceiptCheck>;
	limitations?: { id?: string; text?: string }[];
	e2ee?: { kem?: string; aead?: string };
}

interface Verdict {
	ok: boolean;
	reason: string;
	model: string;
	verifiedAt: string;
	instance: string;
	gpus: number;
	passed: number;
	total: number;
	checks: { label: string; ok: boolean; why: string }[];
	limitations: string[];
	transport: string;
	receiptPath: string;
	sealing: string;
	readAt: string;
}

function unverified(reason: string): Verdict {
	return {
		ok: false, reason, model: "", verifiedAt: "", instance: "", gpus: 0, passed: 0, total: 0, checks: [],
		limitations: [], transport: "", receiptPath: "", sealing: "", readAt: new Date().toISOString(),
	};
}

function verdictOf(r: Receipt): Verdict {
	const checks = Object.entries(r.checks ?? {}).map(([name, c]) => ({
		label: String(c.label ?? name), ok: c.ok === true, why: String(c.why ?? ""),
	}));
	const passed = checks.filter((c) => c.ok).length;
	const confidential = r.verdict === "confidential";
	const ok = confidential && checks.length > 0 && passed === checks.length;
	const reason = ok ? "" : !confidential
		? `session ${r.verdict ?? "unknown"}${r.refusal ? `: ${r.refusal}` : ""}`
		: checks.length === 0 ? "no checks recorded" : `${checks.length - passed} check(s) failed`;
	return {
		ok, reason,
		model: String(r.model_short ?? ""),
		verifiedAt: String(r.verified_at || r.started_at || ""),
		instance: String(r.instance?.id ?? "").slice(0, 8),
		gpus: Number(r.instance?.gpu_count ?? 0),
		passed, total: checks.length, checks,
		limitations: (r.limitations ?? []).map((l) => String(l.text ?? "")).filter(Boolean),
		transport: String(r.transport ?? ""),
		receiptPath: String(r.path ?? ""),
		sealing: [r.e2ee?.kem, r.e2ee?.aead].filter(Boolean).join(" + "),
		readAt: new Date().toISOString(),
	};
}

async function readVerdict(): Promise<Verdict> {
	if (!ENDPOINT) return unverified("this session was not given a local sealed endpoint");
	try {
		const res = await fetch(`${ENDPOINT}/confidential/receipt`, {
			headers: ENDPOINT_KEY ? { authorization: `Bearer ${ENDPOINT_KEY}` } : {},
			signal: AbortSignal.timeout(5_000),
		});
		if (!res.ok) return unverified(`the local sealed endpoint answered ${res.status}`);
		return verdictOf((await res.json()) as Receipt);
	} catch {
		return unverified("the local sealed endpoint did not answer");
	}
}

// Local wall-clock HH:MM — the attorney's clock, not UTC.
function hhmm(iso: string): string {
	const d = new Date(iso);
	return Number.isNaN(d.getTime()) ? iso.slice(11, 16) : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

// Plain words first; the checks themselves are one expand away (/proof). Same vocabulary as the launch card
// (probant_trust.py): "sealed machine", "checked at", "nothing is sent".
function statusText(v: Verdict): string {
	if (!v.ok) return `⛔ AI: sealed machine NOT verified, so nothing is sent (${v.reason})`;
	return `🔒 AI: sealed machine, checked at ${hhmm(v.verifiedAt)}`;
}

function showStatus(ctx: ExtensionContext, v: Verdict): void {
	if (!ctx.hasUI) return;
	const theme = ctx.ui.theme;
	ctx.ui.setStatus(STATUS_KEY, theme ? theme.fg(v.ok ? "success" : "error", statusText(v)) : statusText(v));
}

function refuse(ctx: ExtensionContext, why: string): void {
	const msg = `Model request blocked: ${why}`;
	if (ctx.hasUI) ctx.ui.notify(msg, "error");
	else process.stderr.write(`${msg}\n`);
	ctx.abort();
}

function renderModelProof(v: Verdict | undefined, expanded: boolean, theme: Theme) {
	const box = new Box(1, 1, (t) => theme.bg("customMessageBg", t));
	const line = (s: string) => box.addChild(new Text(s, 0, 0));
	if (!v) {
		line(theme.fg("error", "no verification record"));
		return box;
	}
	line(v.ok
		? theme.fg("success", theme.bold(`🔒 The AI runs in a sealed machine this computer checked at ${hhmm(v.verifiedAt)}`))
		: theme.fg("error", theme.bold(`⛔ The AI's sealed machine could NOT be verified (${v.reason}), so nothing is sent to it.`)));
	if (v.ok) line("Genuine sealed hardware running a build InferRoute has on record. Your text is encrypted here; only that machine can open it.");
	line(theme.fg("dim", "Checked by this computer, not by the AI, and never shown to the AI."));
	if (CONTRACT.modified) {
		line(theme.fg("warning", theme.bold("⚠ contract modified: the mission contract on disk differs from the pinned version.")));
	} else if (CONTRACT.contract_sha) {
		line(`${theme.fg("muted", "contract ")} ${CONTRACT.contract_sha.slice(0, 12)}… (pinned)`);
	}
	if (v.model) line(`${theme.fg("muted", "model    ")} ${v.model}${v.gpus ? ` · ${v.gpus} GPUs` : ""}${v.instance ? ` · instance ${v.instance}` : ""}`);
	if (v.sealing) line(`${theme.fg("muted", "sealing  ")} ${v.sealing}, keys made on this machine`);
	if (v.transport) line(`${theme.fg("muted", "carrier  ")} ${v.transport}`);
	if (v.total) {
		line(`${theme.fg("muted", "checks   ")} ${v.passed}/${v.total} passed${expanded ? "" : " (expand for the technical list)"}`);
		for (const c of v.checks) {
			if (!expanded && c.ok) continue;
			line(`  ${c.ok ? theme.fg("success", "✓") : theme.fg("error", "✗")} ${c.label}${expanded && c.why ? theme.fg("dim", ` · ${c.why}`) : ""}`);
		}
	}
	if (v.limitations.length) {
		line(theme.fg("warning", `not proven (${v.limitations.length})${expanded ? ":" : ", expand to read"}`));
		if (expanded) for (const l of v.limitations) line(theme.fg("dim", `  ○ ${l}`));
	}
	if (v.receiptPath) line(theme.fg("dim", `receipt  ${v.receiptPath}`));
	return box;
}

// ───────────────────────── search enclave ─────────────────────────

interface SearchStep {
	ok: boolean;
	step: string;
	detail: string;
}

interface SearchVerdict {
	ok: boolean;
	reference?: { ok?: boolean; published?: string; key_prefix?: string };
	refusal?: string | null;
	test_roots?: boolean;
	steps: SearchStep[];
	enclave?: {
		measurement?: string;
		host_data?: string;
		uvm_svn?: number;
		index_snapshot?: string;
		lifetime_id?: string;
		enclave_key?: string;
		pipeline_version?: string;
	};
	statement?: { hits_n?: number; outcome?: string; refusal?: string; search_seconds?: number; pipeline_version?: string };
	result?: { hits?: { key: string; year?: number; title?: string; score?: number }[]; claim_boundary?: string; candidates?: number };
}

interface SearchProof {
	ok: boolean;
	refusal: string;
	testRoots: boolean;
	ours: boolean;
	phase: "verify" | "search" | "declined";
	steps: SearchStep[];
	measurement: string;
	policy: string;
	index: string;
	enclaveKey: string;
	hits: number;
	// The documents themselves, for a surface that shows results (the local browser page). Tool `details`
	// never reach the model; the model gets hitsText in `content`.
	docs: { key: string; year?: number; title?: string; alsoIn?: number }[];
	// What this search was, as the professional sees it on the card: its number in the session, the feature it
	// covered, the document it looked for neighbours of, and how many references were asked for.
	searchNo?: number;
	feature?: string;
	like?: string;
	k?: number;
	at: string;
}

// `depth`, in the words the tool offers the model; the numbers are what the card says, never "a deeper search".
const DEPTH_K: Record<string, number> = { quick: 10, standard: 25, broad: 50 };

// `checked`: for a search, the verification that preceded it. The search response itself does not repeat the
// reference block; but the search was pinned to that enclave's lifetime and the verifier re-runs the identity
// check on every search, so a successful search on the SAME enclave inherits the identity it was checked under.
function searchProofOf(out: SearchVerdict, phase: SearchProof["phase"], checked?: SearchVerdict): SearchProof {
	return {
		ok: out.ok && phase !== "declined",
		refusal: phase === "declined" ? "the user declined to send a sealed query" : String(out.refusal ?? ""),
		testRoots: out.test_roots === true,
		ours: isInferRoutes(out) || Boolean(checked && out.ok && isInferRoutes(checked)
			&& out.enclave?.host_data === checked.enclave?.host_data && out.enclave?.lifetime_id === checked.enclave?.lifetime_id),
		phase,
		steps: out.steps ?? [],
		measurement: String(out.enclave?.measurement ?? ""),
		policy: String(out.enclave?.host_data ?? ""),
		index: String(out.enclave?.index_snapshot ?? ""),
		enclaveKey: String(out.enclave?.enclave_key ?? ""),
		hits: Number(out.statement?.hits_n ?? 0),
		docs: (out.result?.hits ?? []).map((h) => ({ key: String(h.key), year: h.year, title: h.title })),
		at: new Date().toISOString(),
	};
}

async function searchCall(path: string, body: unknown, signal: AbortSignal | undefined): Promise<SearchVerdict> {
	const timeout = AbortSignal.timeout(SEARCH_TIMEOUT_MS);
	const res = await fetch(`${SEARCH}${path}`, {
		method: body === undefined ? "GET" : "POST",
		headers: body === undefined ? undefined : { "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
		signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
	});
	return (await res.json()) as SearchVerdict;
}

interface LifecycleStatus {
	managed?: boolean;
	running?: boolean;
	started_at?: number;
	container_hours?: number;
	cost_estimate?: number;
	budget_hours?: number;
	budget_hours_remaining?: number;
	over_budget?: boolean;
	seconds_until_idle_reap?: number | null;
}

// The enclave lifecycle is host-managed by the verifier. The extension reads it back only to show the
// attorney the budget and to keep the container warm while they read; it never manages Azure itself.
async function lifecycleCall(path: string, post: boolean): Promise<LifecycleStatus | null> {
	if (!SEARCH) return null;
	try {
		const res = await fetch(`${SEARCH}${path}`, {
			method: post ? "POST" : "GET",
			headers: post ? { "content-type": "application/json" } : undefined,
			body: post ? "{}" : undefined,
			signal: AbortSignal.timeout(10_000),
		});
		return (await res.json()) as LifecycleStatus;
	} catch {
		return null;
	}
}

function lifecycleLine(s: LifecycleStatus): string {
	const hrs = typeof s.container_hours === "number" ? s.container_hours.toFixed(2) : "?";
	const budget = typeof s.budget_hours === "number" ? ` / ${s.budget_hours.toFixed(1)}h ceiling` : "";
	const started = s.started_at ? ` · up since ${new Date(s.started_at * 1000).toLocaleTimeString()}` : "";
	const over = s.over_budget ? " ⚠ over ceiling" : "";
	return `search enclave: ${s.running ? "running" : "not running"}${started} · ${hrs}h used${budget}${over}`;
}

function showLifecycle(ctx: ExtensionContext, s: LifecycleStatus | null): void {
	if (!ctx.hasUI || !s || !s.managed) return;
	const t = ctx.ui.theme;
	const text = lifecycleLine(s);
	ctx.ui.setStatus(LIFECYCLE_STATUS_KEY, t ? t.fg(s.over_budget ? "warning" : "dim", text) : text);
}

function searchStatus(ctx: ExtensionContext, p: SearchProof): void {
	if (!ctx.hasUI) return;
	const t = ctx.ui.theme;
	const text = p.ok
		? p.testRoots
			? `◐ Search: TEST machine, not a real verification`
			: `🔒 Search: ${p.ours ? "InferRoute's sealed machine" : "sealed machine"}, checked at ${hhmm(p.at)}${p.phase === "search" ? ` · ${p.hits} results` : ""}`
		: `⛔ Search: ${plainRefusal(p.refusal)}`;
	ctx.ui.setStatus(SEARCH_STATUS_KEY, t ? t.fg(p.ok && !p.testRoots ? "success" : p.ok ? "warning" : "error", text) : text);
}

// Same rule as probant_trust.search_is_inferroutes: the reference is authentic AND this enclave matched it.
function isInferRoutes(v: SearchVerdict): boolean {
	return v.ok && v.reference?.ok === true && (v.steps ?? []).some((s) => s.ok && s.step.startsWith("enclave identity"));
}

function fmtDate(yyyymmdd: number | string): string {
	const d = String(yyyymmdd);
	return /^\d{8}$/.test(d) ? `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}` : d;
}

function plainRefusal(refusal: string): string {
	const r = refusal.toLowerCase();
	if (["did not answer", "unreachable", "connection", "timed out", "timeout"].some((m) => r.includes(m))) {
		return "the search machine isn't answering; nothing was sent";
	}
	if (r.includes("declined")) return "you declined; nothing was sent";
	return `not verified, so nothing was sent (${refusal})`;
}

function renderSearchProof(p: SearchProof | undefined, expanded: boolean, theme: Theme) {
	const box = new Box(1, 1, (t) => theme.bg("customMessageBg", t));
	const line = (s: string) => box.addChild(new Text(s, 0, 0));
	if (!p) {
		line(theme.fg("error", "no search verification record"));
		return box;
	}
	const passed = p.steps.filter((s) => s.ok).length;
	if (p.ok) {
		line(theme.fg("success", theme.bold(p.phase === "search"
			? `🔒 Sealed search${p.searchNo ? ` ${p.searchNo}` : ""}${p.feature ? ` · ${p.feature}` : ""}${p.like ? ` · like ${p.like}` : ""}: ${p.hits} results, opened on this computer only`
			: "🔒 The search machine is a sealed machine this computer just checked")));
		line(`Genuine sealed hardware running ${p.ours ? "exactly the software InferRoute published (signed reference checked)" : "exactly the software this computer expects"}. The search text was encrypted here; only that machine could open it.`);
	} else {
		line(theme.fg("error", theme.bold(`⛔ Search: ${plainRefusal(p.refusal)}`)));
	}
	if (p.testRoots) line(theme.fg("warning", theme.bold("TEST machine: checked against test keys, not a real verification")));
	line(theme.fg("dim", "Checked by this computer, not by the AI, and never shown to the AI."));
	if (p.measurement) line(`${theme.fg("muted", "utility VM ")} ${p.measurement.slice(0, 24)}…`);
	if (p.policy) line(`${theme.fg("muted", "policy     ")} ${p.policy.slice(0, 24)}…`);
	if (p.index) line(`${theme.fg("muted", "index      ")} ${corpusPhrase(p.index)}`);
	if (p.enclaveKey) line(`${theme.fg("muted", "sealed to  ")} ${p.enclaveKey}…`);
	line(`${theme.fg("muted", "checks     ")} ${passed}/${p.steps.length} passed${expanded ? "" : " (expand for the technical list)"}`);
	for (const s of p.steps) {
		if (!expanded && s.ok) continue;
		line(`  ${s.ok ? theme.fg("success", "✓") : theme.fg("error", "✗")} ${s.step}${expanded ? theme.fg("dim", ` · ${s.detail}`) : ""}`);
	}
	// THE DOCUMENTS THEMSELVES. Without them the terminal showed only the checks, so the only way the
	// professional saw what came back was the model retyping all of it — a minute of typing, and a list it
	// could get wrong. Shown here, from the tool's own result, the model does not have to repeat it.
	const docs = p.docs ?? [];
	if (docs.length) {
		const shown = expanded ? docs : docs.slice(0, 10);
		line("");
		for (const [i, d] of shown.entries()) {
			const mark = d.key;
			line(`  ${String(i + 1).padStart(2)}. ${theme.bold(mark)}${d.year ? theme.fg("muted", ` (${d.year})`) : ""} ${String(d.title ?? "").slice(0, 96)}`);
		}
		if (!expanded && docs.length > shown.length) line(theme.fg("dim", `  … ${docs.length - shown.length} more (expand)`));
		line(theme.fg("dim", "  mark one: /relevant <number> · /not-relevant · /known"));
	}
	return box;
}

// The corpus, said in a way a patent attorney reads rather than decodes. "patent1m-epwo+usall@29595902"
// is the signed identifier and stays exactly that everywhere it is verified; this is the sentence beside
// it. Henry, 24 Sep, on seeing the agent repeat the raw string in its answer.
//
// It refuses rather than guesses. An identifier it does not recognise gets no friendly name at all — a
// corpus described as covering territories it does not cover would be worse than one that looks technical.
function corpusName(id: string): string {
	const m = /^[a-z0-9]+-([a-z+]+)@(\d+)$/i.exec(String(id || "").trim());
	if (!m) return "";
	const where: string[] = [];
	const scope = m[1].toLowerCase();
	if (scope.includes("us")) where.push("the United States");
	if (scope.includes("ep")) where.push("Europe");
	if (scope.includes("wo")) where.push("WIPO");
	if (!where.length) return "";
	const n = Number(m[2]);
	if (!Number.isFinite(n) || n <= 0) return "";
	const count = n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")} million` : n.toLocaleString("en");
	const places = where.length > 1 ? `${where.slice(0, -1).join(", ")} and ${where[where.length - 1]}` : where[0];
	return `${count} published patents from ${places}`;
}

// Name first, identifier second and never dropped: the name is for reading, the identifier is what a
// statement commits to and what an auditor checks.
function corpusPhrase(id: string): string {
	const name = corpusName(id);
	return name ? `${name} (${id})` : (id || "the index");
}

function hitsText(out: SearchVerdict, label: string, earlier: Map<string, number>): string {
	const hits = out.result?.hits ?? [];
	const lines = [
		`${label}: ${hits.length} references surfaced by a sealed search over ${corpusPhrase(String(out.enclave?.index_snapshot ?? ""))}. ` +
		`${out.result?.claim_boundary ?? "It surfaces related art; it does not certify completeness or absence."}`,
		"The professional's screen already lists these documents with their numbers, years and titles, and the " +
		"controls to mark them. Do NOT retype the list. Say what is worth saying about it — which part of the " +
		"disclosure this search covered, what recurs across searches, what is worth looking at next — and cite a " +
		"document by its number when you discuss it.",
	];
	hits.forEach((h, i) => {
		const seen = earlier.get(String(h.key));
		lines.push(`${i + 1}. ${h.key}${h.year ? ` (${h.year})` : ""}${h.title ? ` ${h.title}` : ""}${seen ? ` [also returned by search ${seen}]` : ""}`);
	});
	return lines.join("\n");
}

// A suggested next step is sent as the professional's own message when they choose it. It must never be a
// command or a shell line: "/relevant X" would record a mark as the professional's, and "!…" runs a shell.
// Next steps built from the professional's marks — worded EXACTLY as the page words them (probant_web/app.js),
// so the page can tell which of them the assistant already offered. A test holds the two files together.
const STEP_DEEPER = "Look deeper at the ones I marked relevant: search their features one at a time and find documents like them";
const STEP_LEAVE_OUT = "Continue the survey, leaving out what I marked known or not relevant";
const STEP_SURVEY = "Run a prior-art survey of the disclosure";
// The deep search. Worded as the professional would ask for it, like every other step: the button SENDS
// this sentence, and the assistant answers it by calling deep_prior_art_search.
const STEP_DEEP = "Search deeply: put the whole disclosure, its features, and my marks to the search machine";
const stepLike = (key: string) => `Find documents like ${key}`;
const NEXT_MAX = 4;
// A button sends EXACTLY its text, so a suggestion is never cut: a cut one sends a broken half-instruction
// ("…to deepen the weakly matched endorsemen…", Henry, 19 Sep). One too long to be a button is dropped whole.
const NEXT_LEN = 400;
function cleanSteps(raw: unknown): string[] {
	const out: string[] = [];
	for (const item of Array.isArray(raw) ? raw : []) {
		let t = String(item ?? "").replace(/\s+/g, " ").trim().replace(/^[\/!\s]+/, "").trim();
		if (t.length < 4) continue;
		if (t.length > NEXT_LEN) continue;
		if (!out.includes(t)) out.push(t);
		if (out.length >= NEXT_MAX) break;
	}
	return out;
}

// ───────────────────────── the extension ─────────────────────────

// ───────────────────────── per-session disclosure record ─────────────────────────
//
// The spine of the product, stated for one session: which surface saw what. Written to
// INFERROUTE_HOME/confidential/attested-sessions/<session>.json on shutdown and after each search.

// The record dir the launcher provides (writable under the fs confinement); falls back to the old
// location only when the launcher did not set it.
const RECORD_DIR = process.env.IR_ATTESTED_RECORD_DIR
	?? (process.env.INFERROUTE_HOME ? join(process.env.INFERROUTE_HOME, "confidential", "attested-sessions") : "");
const CONFINED = (process.env.IR_ATTESTED_CONFINE ?? "").trim().toLowerCase() !== "off";
const CONTRACT = {
	contract_sha: process.env.IR_CONTRACT_SHA ?? "",
	preamble_sha: process.env.IR_PREAMBLE_SHA ?? "",
	modified: (process.env.IR_CONTRACT_MODIFIED ?? "0") === "1",
	config_hash: process.env.IR_CONFIG_HASH ?? "",
	pi_version: process.env.IR_PI_VERSION ?? "",
};

interface SearchRecord {
	at: string;
	ok: boolean;
	testRoots: boolean;
	measurement: string;
	policy: string;
	index: string;
	hits: number;
	refusal: string;
}

class SessionRecord {
	sessionId = "";
	startedAt = new Date().toISOString();
	modelOk = false;
	modelChecks = "";
	modelReceipt = "";
	modelCheckList: { label: string; ok: boolean; why: string }[] = [];
	modelLimitations: string[] = [];
	modelDetail: Record<string, unknown> = {};
	searchOffered = false;
	searches: SearchRecord[] = [];
	// One entry per deep-search press: which sub-queries were put, and what became of each. The sealed
	// statements for those queries are already rows in `searches`; this says which press they belonged to
	// and — the part a list of successes cannot say — which sub-queries failed or came back empty.
	fanouts: Record<string, unknown>[] = [];

	surfaces() {
		return {
			this_device: "opened everything: the conversation, the model's replies, and the sealed search results",
			model_enclave: this.modelOk
				? "saw the conversation content, inside an enclave this device verified; nothing else could read it in transit"
				: "not verified; no request was sent to it",
			search_enclave: this.searches.length
				? `saw ${this.searches.length} query(ies), each sealed on this device to a key its hardware report committed to; not their surrounding conversation`
				: "saw nothing (no sealed search ran)",
			inferroute_and_cloud_hosts: "saw ciphertext, message sizes and timing only — never the words",
			user_extensions: "saw nothing: extension discovery was disabled for this session",
			network: CONFINED
				? "the agent's process tree was confined to the two local verifying proxies (see the residual in the model panel)"
				: "not confined this session",
		};
	}

	toJSON() {
		return {
			schema: "inferroute.attested-session/1",
			session_id: this.sessionId,
			// Which screen the professional used ("terminal" or "browser"), for the home page's history.
			surface: process.env.IR_PROBANT_SURFACE ?? "",
			started_at: this.startedAt,
			written_at: new Date().toISOString(),
			contract: {
				contract_sha: CONTRACT.contract_sha,
				preamble_sha: CONTRACT.preamble_sha,
				modified: CONTRACT.modified,
				config_hash: CONTRACT.config_hash,
				pi_version: CONTRACT.pi_version,
				index_snapshot: this.searches[0]?.index ?? "",
			},
			model_lane: {
				verified: this.modelOk, checks: this.modelChecks, receipt: this.modelReceipt,
				check_list: this.modelCheckList, limitations: this.modelLimitations, ...this.modelDetail,
			},
			search_lane: { offered: this.searchOffered, searches: this.searches, deep_searches: this.fanouts },
			which_surface_saw_what: this.surfaces(),
			note: "A per-surface disclosure record for one attested session. Each line is a checked fact, not a promise.",
		};
	}

	write(): string | null {
		const rec = this.toJSON();
		// D1: when there is a host verifier, IT writes the record to a file outside the sandbox — the agent
		// can neither reach this endpoint (no HTTP tool) nor write that file (confinement). We only post the
		// content, composed from the model receipt and search proofs the agent does not control.
		if (SEARCH) {
			fetch(`${SEARCH}/record`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ record: rec }),
				signal: AbortSignal.timeout(5_000),
			}).catch(() => {});
			return `${SEARCH}/record (host-written)`;
		}
		// No search enclave (developer model-only session): fall back to a local file, agent-writable —
		// there is no host verifier to own it. Not the attorney path.
		if (!RECORD_DIR || !this.sessionId) return null;
		try {
			mkdirSync(RECORD_DIR, { recursive: true });
			const path = join(RECORD_DIR, `${this.sessionId}.json`);
			writeFileSync(path, `${JSON.stringify(rec, null, 1)}\n`);
			return path;
		} catch {
			return null;
		}
	}
}

export default function (pi: ExtensionAPI) {
	let timer: ReturnType<typeof setInterval> | undefined;
	const disclosure = new SessionRecord();
	// In-session memory of searches: which search first returned each document, each document's returned text
	// (for `like`), and the last next steps offered (for /next).
	let searchNo = 0;
	// Approval questions in flight, by machine measurement — shared by searches issued at the same instant.
	const approvals = new Map<string, Promise<boolean>>();
	const firstSeen = new Map<string, number>();
	const docText = new Map<string, string>();
	// Documents this matter's searches returned in EARLIER sessions (the launcher writes them; numbers and public
	// titles only), so "like" and the marks note work for them too — not only for this session's results.
	const priorDocs = new Map<string, string>();
	try {
		const f = process.env.IR_MATTER_DOCS;
		if (f) for (const [k, t] of Object.entries(JSON.parse(readFileSync(f, "utf8")) as Record<string, string>)) priorDocs.set(k, String(t));
	} catch {
		/* no earlier documents is a normal state, never a failure */
	}
	let lastSteps: string[] = [];

	pi.registerEntryRenderer<Verdict>(PROOF_ENTRY, (entry, { expanded }, theme) => renderModelProof(entry.data, expanded, theme));
	pi.registerEntryRenderer<SearchProof>(SEARCH_PROOF_ENTRY, (entry, { expanded }, theme) => renderSearchProof(entry.data, expanded, theme));

	async function record(ctx: ExtensionContext): Promise<Verdict> {
		const v = await readVerdict();
		showStatus(ctx, v);
		pi.appendEntry<Verdict>(PROOF_ENTRY, v);
		disclosure.modelOk = v.ok;
		disclosure.modelChecks = v.total ? `${v.passed}/${v.total}` : "";
		disclosure.modelReceipt = v.receiptPath;
		// The full check list and the receipt's own stated limitations, so the export can show exactly what
		// was and was not proven for the model lane — not just a pass count.
		disclosure.modelCheckList = v.checks.map((c) => ({ label: c.label, ok: c.ok, why: c.why }));
		disclosure.modelLimitations = [...v.limitations];
		disclosure.modelDetail = { model: v.model, verified_at: v.verifiedAt, instance: v.instance, gpus: v.gpus,
			transport: v.transport, sealing: v.sealing, reason: v.reason };
		disclosure.write();
		return v;
	}

	pi.on("session_start", async (_event, ctx) => {
		if (TOOLS.size) pi.setActiveTools(pi.getActiveTools().filter((t) => TOOLS.has(t)));
		try {
			disclosure.sessionId = ctx.sessionManager.getSessionId() ?? "";
		} catch {
			disclosure.sessionId = "";
		}
		disclosure.searchOffered = Boolean(SEARCH);
		if (CONTRACT.modified && ctx.hasUI) {
			ctx.ui.notify("The mission contract on disk differs from the pinned version — running as modified. This is recorded.", "warning");
		}
		await record(ctx);
		if (SEARCH && ctx.hasUI) {
			const t = ctx.ui.theme;
			const text = "Search: checking the sealed machine…";
			ctx.ui.setStatus(SEARCH_STATUS_KEY, t ? t.fg("dim", text) : text);
			// A real check now, so the footer never implies a search machine that isn't there. Not awaited:
			// the offer fetch can take seconds and the attorney should be able to type meanwhile.
			searchCall("/enclave", undefined, undefined)
				.then((v) => searchStatus(ctx, searchProofOf(v, "verify")))
				.catch(() => searchStatus(ctx, searchProofOf({ ok: false, refusal: "the local search verifier did not answer", steps: [] }, "verify")));
			showLifecycle(ctx, await lifecycleCall("/lifecycle", false));
		}
		// The terminal gets a how-to; the browser page has its own welcome, and "/quit" means nothing there.
		if (ctx.hasUI && MATTER && process.env.IR_PROBANT_SURFACE !== "browser") {
			ctx.ui.notify(
				[`Matter ${MATTER}.`,
					"Ask for a prior-art survey of the disclosure in this folder.",
					"Mark results: /relevant <number> (also /not-relevant, /known, /marks). Send a suggested next step: /next <n>. Show the checks again: /proof.",
					`Leave with /quit, then keep the record: ir probant export ${MATTER}`].join("\n"),
				"info",
			);
		}
		if (timer) clearInterval(timer);
		timer = setInterval(async () => showStatus(ctx, await readVerdict()), REFRESH_MS);
		timer.unref?.();
	});

	pi.on("session_shutdown", async () => {
		if (timer) clearInterval(timer);
		timer = undefined;
		disclosure.write();
	});

	pi.registerCommand("disclosure", {
		description: "Show and write this session's record of which surface saw what",
		handler: async (_args, ctx) => {
			const path = disclosure.write();
			if (!ctx.hasUI) return;
			const s = disclosure.surfaces();
			const lines = Object.entries(s).map(([k, v]) => `  ${k.replace(/_/g, " ")}: ${v}`);
			ctx.ui.notify(
				["Which surface saw what, this session:", ...lines, path ? `written to ${path}` : "(not written: no session id or home)"].join("\n"),
				"info",
			);
		},
	});

	pi.on("turn_end", async (_event, ctx) => {
		showStatus(ctx, await readVerdict());
	});

	pi.on("turn_start", async (_event, ctx) => {
		// User input is activity: keep the container warm and refresh the budget line. Best-effort.
		if (SEARCH) showLifecycle(ctx, await lifecycleCall("/activity", true));
	});

	pi.registerCommand("proof", {
		description: "Re-check the model enclave's verification and show the proof card",
		handler: async (_args, ctx) => {
			await record(ctx);
		},
	});

	pi.on("before_provider_request", async (_event, ctx) => {
		const model = ctx.model as { provider?: string; baseUrl?: string } | undefined;
		const base = String(model?.baseUrl ?? "").replace(/\/+$/, "");
		if (!ENDPOINT || model?.provider !== PROVIDER || base !== `${ENDPOINT}/v1`) {
			refuse(ctx, "this session sends model requests only to its verified local sealed endpoint");
			return;
		}
		const v = await readVerdict();
		showStatus(ctx, v);
		if (!v.ok) refuse(ctx, v.reason);
	});

	pi.on("model_select", async (event, ctx) => {
		if (event.model.provider === PROVIDER) return;
		if (ctx.hasUI) ctx.ui.notify("That model is not the verified enclave; its requests would be blocked. Switching back.", "error");
		if (event.previousModel?.provider === PROVIDER) await pi.setModel(event.previousModel);
	});

	pi.on("tool_call", async (event) => {
		if (TOOLS.size && !TOOLS.has(event.toolName)) {
			return { block: true, reason: `${event.toolName} is not available in an attested session` };
		}
	});

	// ── reading a document and proposing matters (intake) ──
	// Registered only when the launcher staged a document. The agent PROPOSES; the professional creates the
	// matter from the page. Each proposal must quote the document, and the host drops any quote it cannot
	// find there — the one error a reader of a summary cannot catch is an invented passage.
	const intakeOut = process.env.IR_INTAKE_OUT ?? "";
	if (intakeOut) {
		pi.registerTool({
			name: "propose_matter",
			label: "Propose a matter",
			description:
				"Propose ONE invention found in the document as a matter the professional may open. Call it once per " +
				"distinct invention, as you find them, and keep reading afterwards — do not wait until the end. `title` " +
				"names the invention in the professional's language; `summary` is a self-contained technical description " +
				"a prior-art search could be run from, in your own words, not a table of contents entry; `quote` is a " +
				"VERBATIM passage from the document that shows the invention (copy it exactly, 20 characters or more — a " +
				"quote that is not in the document is discarded and your proposal with it); `priority_date` only when the " +
				"document states one, as YYYY-MM-DD. Proposing a matter does not create anything: the professional " +
				"decides, names it, and opens it.",
			promptSnippet: "Propose one invention from the document as a matter (quote the document)",
			parameters: Type.Object({
				title: Type.String(),
				summary: Type.String(),
				quote: Type.String(),
				priority_date: Type.Optional(Type.String()),
				source: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				const row = {
					title: String(params.title ?? "").trim(),
					summary: String(params.summary ?? "").trim(),
					quote: String(params.quote ?? "").trim(),
					priority_date: String(params.priority_date ?? "").trim(),
					// Which document the quote is from. With several in the directory the host checks each
					// quote against THIS file, so a passage from another one cannot be attributed here.
					source: String(params.source ?? "").trim(),
					at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
				};
				if (!row.title || !row.summary || row.quote.length < 20) {
					throw new Error("propose_matter needs a title, a self-contained summary, and a verbatim quote of 20 characters or more from the document; nothing was recorded");
				}
				try {
					mkdirSync(intakeOut.replace(/\/[^/]*$/, ""), { recursive: true });
					writeFileSync(intakeOut, JSON.stringify(row) + "\n", { flag: "a", mode: 0o600 });
				} catch (e) {
					throw new Error(`the proposal could not be recorded on this computer: ${(e as Error).message}`);
				}
				return {
					content: [{ type: "text", text: `Recorded: "${row.title}". The professional will see it with your quote and decide. Keep reading the document.` }],
					details: { title: row.title },
				};
			},
			renderResult(result, _options, theme) {
				const title = (result.details as { title?: string } | undefined)?.title ?? "";
				const box = new Box(1, 0, (t) => theme.bg("customMessageBg", t));
				box.addChild(new Text(theme.bold("Proposed matter") + (title ? `  ${title}` : ""), 0, 0));
				return box;
			},
		});
	}

	// ── recording many findings at once ──
	// One call per finding costs a model turn per finding: measured 20 Sep, 31 findings from 60 KB took
	// thirteen minutes, ~25 s each, while the reading itself was three calls. Over a 3 MB portfolio that is
	// eleven hours of round trips for work the model has already done. This takes them in one call.
	const batchOut = process.env.IR_INTAKE_OUT ?? "";
	if (batchOut) {
		pi.registerTool({
			name: "record_findings",
			label: "Record findings",
			description:
				"Record EVERY finding you have for the part you just read, in ONE call: `findings` is an array of " +
				"{title, summary, quote, source, priority_date?}. Same rules as one at a time — the quote must be " +
				"VERBATIM from the document named in `source`, twenty characters or more, and a finding whose quote " +
				"is not in that document is discarded. Prefer this over calling propose_matter repeatedly: it is the " +
				"same work in one round trip. Call it as you finish each part of the document rather than saving " +
				"everything for the end.",
			promptSnippet: "Record all findings for this part in one call",
			parameters: Type.Object({
				findings: Type.Array(Type.Object({
					title: Type.String(),
					summary: Type.String(),
					quote: Type.String(),
					source: Type.Optional(Type.String()),
					priority_date: Type.Optional(Type.String()),
				}), { minItems: 1 }),
			}),
			async execute(_toolCallId, params) {
				const at = new Date().toISOString().replace(/\.\d+Z$/, "Z");
				const rows = (params.findings ?? []).map((f) => ({
					title: String(f.title ?? "").trim(),
					summary: String(f.summary ?? "").trim(),
					quote: String(f.quote ?? "").trim(),
					source: String(f.source ?? "").trim(),
					priority_date: String(f.priority_date ?? "").trim(),
					at,
				})).filter((r) => r.title && r.summary && r.quote.length >= 20);
				if (!rows.length) {
					throw new Error("record_findings needs at least one finding with a title, a summary and a verbatim quote of 20 characters or more; nothing was recorded");
				}
				try {
					mkdirSync(batchOut.replace(/\/[^/]*$/, ""), { recursive: true });
					writeFileSync(batchOut, rows.map((r) => JSON.stringify(r)).join("\n") + "\n", { flag: "a", mode: 0o600 });
				} catch (e) {
					throw new Error(`the findings could not be recorded on this computer: ${(e as Error).message}`);
				}
				const dropped = (params.findings ?? []).length - rows.length;
				return {
					content: [{ type: "text", text: `Recorded ${rows.length} finding(s)${dropped ? `, ${dropped} incomplete and skipped` : ""}. Carry on reading; call this again for the next part.` }],
					details: { n: rows.length },
				};
			},
			renderResult(result, _options, theme) {
				const n = (result.details as { n?: number } | undefined)?.n ?? 0;
				const box = new Box(1, 0, (t) => theme.bg("customMessageBg", t));
				box.addChild(new Text(theme.bold("Findings recorded") + `  ${n}`, 0, 0));
				return box;
			},
		});
	}

	// ── clustering a portfolio, round after round ──
	// One call per cluster, each naming the candidates it holds. The host checks the partition (every
	// candidate exactly once), compares it with the previous round's, and decides whether it has converged:
	// an agent asked "have you converged?" says yes, and a partition compared with its predecessor cannot.
	// ── the synthesis pass: every finding in the portfolio, in one context ──
	// The corpus itself does not fit any context on this lane (measured 20 Sep: 2.46 M tokens against a 1 M
	// ceiling). What it ASSERTS does — roughly 90 k tokens of findings — so this is the step that genuinely
	// sees the whole portfolio at once, and every theme it draws must name the findings it rests on.
	const clusterOut = process.env.IR_CLUSTER_OUT ?? "";
	if (clusterOut) {
		pi.registerTool({
			name: "propose_cluster",
			label: "Propose a theme",
			description:
				"Record ONE theme or matter of the portfolio per call, until every finding worth placing is in exactly one of them. `label` names it in a few words; `thesis` is one sentence saying what the " +
				"members have in common that matters technically — not a category name, the actual claim; `members` is " +
				"the list of candidate ids (c1, c2 …) exactly as given; `why` is what made you put these together and " +
				"leave others out. Do not invent ids, do not leave a candidate out because it fits badly — put it where " +
				"it fits least badly and say so in `why`, or give it a cluster of its own. " +
				"When the portfolio has a register, also give `register` (the ids it covers, e.g. P3, TA-L3), " +
				"`aspects` (the features that matter to a claim, one short line each) and `detail` (anything a reader " +
				"would want beside them — variants, dependencies, what it does NOT cover — kept compact).",
			promptSnippet: "Group the candidates into themes (one call per cluster, all candidates covered)",
			parameters: Type.Object({
				label: Type.String(),
				thesis: Type.String(),
				members: Type.Array(Type.String(), { minItems: 1 }),
				why: Type.Optional(Type.String()),
				// Optional, so a portfolio without a register keeps working exactly as before.
				register: Type.Optional(Type.Array(Type.String())),
				aspects: Type.Optional(Type.Array(Type.String())),
				detail: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				const row = {
					label: String(params.label ?? "").trim(),
					thesis: String(params.thesis ?? "").trim(),
					members: (params.members ?? []).map((m) => String(m).trim()).filter(Boolean),
					why: String(params.why ?? "").trim(),
					register: (params.register ?? []).map((m) => String(m).trim()).filter(Boolean),
					aspects: (params.aspects ?? []).map((m) => String(m).trim()).filter(Boolean),
					detail: String(params.detail ?? "").trim(),
					at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
				};
				if (!row.label || !row.members.length) {
					throw new Error("propose_cluster needs a label and at least one candidate id; nothing was recorded");
				}
				try {
					mkdirSync(clusterOut.replace(/\/[^/]*$/, ""), { recursive: true });
					writeFileSync(clusterOut, JSON.stringify(row) + "\n", { flag: "a", mode: 0o600 });
				} catch (e) {
					throw new Error(`the cluster could not be recorded on this computer: ${(e as Error).message}`);
				}
				return {
					content: [{ type: "text", text: `Recorded "${row.label}" with ${row.members.length} candidate(s). Continue until every candidate is in exactly one cluster.` }],
					details: { label: row.label, n: row.members.length },
				};
			},
			renderResult(result, _options, theme) {
				const d = result.details as { label?: string; n?: number } | undefined;
				const box = new Box(1, 0, (t) => theme.bg("customMessageBg", t));
				box.addChild(new Text(theme.bold("Cluster") + `  ${d?.label ?? ""} (${d?.n ?? 0})`, 0, 0));
				return box;
			},
		});
	}

	if (!SEARCH) return;

	// ── one sealed search, end to end ──────────────────────────────────────────────────────────────
	//
	// Verify the machine, clear the approval once per machine per matter, send, record the proof, number it.
	// `prior_art_search` and the deep fan-out both come through here, and that is the point: the question
	// "did the professional agree to this machine" must have ONE answer in this extension. A second copy of
	// that logic is a second opinion about consent, and the two would drift the first time either changed.
	async function sealedSearch(o: {
		text: string; k: number; feature?: string; like?: string;
		ctx: ExtensionContext; signal: AbortSignal | undefined; phase: (name: string) => void;
	}): Promise<{ sp: SearchProof; out: SearchVerdict; earlier: Map<string, number> }> {
		const { text, k, ctx, signal } = o;
		const feature = o.feature ?? "";
		const like = o.like ?? "";
		let verified: SearchVerdict;
		o.phase("verifying");
		try {
			verified = await searchCall("/enclave", undefined, signal);
		} catch {
			throw new Error("the local search verifier did not answer; nothing was sent");
		}
		const vp = searchProofOf(verified, "verify");
		searchStatus(ctx, vp);
		if (!verified.ok) {
			pi.appendEntry<SearchProof>(SEARCH_PROOF_ENTRY, vp);
			throw new Error(`the search enclave did not verify (${vp.refusal}); nothing was sent`);
		}
		const e = verified.enclave ?? {};
		let matter: { approved?: string[]; cutoff_date?: number | null } = {};
		try {
			matter = (await searchCall("/matter/state", undefined, signal)) as unknown as typeof matter;
		} catch {
			matter = {};
		}
		const measurement = String(e.measurement ?? "");
		if (!(matter.approved ?? []).includes(measurement)) {
			o.phase("approval");
			let pending = approvals.get(measurement);
			if (!pending) {
				const bound = matter.cutoff_date ? `published before ${fmtDate(matter.cutoff_date)}` : "within the matter's date bound";
				const identity = isInferRoutes(verified)
					? "running exactly the software InferRoute published (signed reference checked)"
					: "running exactly the software this computer expects";
				const preview = text.length > 400 ? `${text.slice(0, 400)}…` : text;
				pending = (async () => {
					const ok = await ctx.ui.confirm(
						"Allow a sealed patent search?",
						[
							vp.testRoots ? "⚠ TEST machine: checked against test keys, not a real verification.\n\n" : "",
							"The assistant wants to search for:\n",
							`  "${preview}"\n\n`,
							`Checked just now: the search machine is genuine sealed hardware, ${identity}. `,
							"This text is encrypted here and only that machine can open it. ",
							`Only documents ${bound} come back.\n\n`,
							"Allow searches to this machine for this matter? You won't be asked again for it.\n",
							`(technical: software ${String(e.host_data ?? "").slice(0, 12)}… · index ${e.index_snapshot ?? ""} · key ${e.enclave_key ?? ""}…)`,
						].join(""),
					);
					if (ok) {
						try {
							await searchCall("/matter/approve", { measurement }, signal);
						} catch {
							/* approval recording is best-effort; the confirm above is the gate */
						}
					}
					return ok;
				})();
				approvals.set(measurement, pending);
				pending.finally(() => approvals.delete(measurement)).catch(() => {});
			}
			const ok = await pending;
			if (!ok) {
				pi.appendEntry<SearchProof>(SEARCH_PROOF_ENTRY, searchProofOf(verified, "declined"));
				throw new Error("the user declined to send a sealed query to the search enclave; nothing was sent");
			}
		}
		let out: SearchVerdict;
		o.phase("searching");
		try {
			out = await searchCall("/search", { text, k, expect_lifetime_id: e.lifetime_id }, signal);
		} catch {
			throw new Error("the local search verifier did not answer; the search did not complete");
		}
		const sp = searchProofOf(out, "search", verified);
		sp.feature = feature || undefined;
		sp.like = like || undefined;
		sp.k = k;
		searchStatus(ctx, sp);
		disclosure.searches.push({
			at: sp.at, ok: sp.ok, testRoots: sp.testRoots, measurement: sp.measurement, policy: sp.policy,
			index: sp.index, hits: sp.hits, refusal: sp.refusal,
		});
		disclosure.write();
		if (!out.ok) {
			pi.appendEntry<SearchProof>(SEARCH_PROOF_ENTRY, sp);
			throw new Error(`the sealed search was refused (${sp.refusal})`);
		}
		searchNo += 1;
		sp.searchNo = searchNo;
		const earlier = new Map<string, number>();
		for (const d of sp.docs) {
			const first = firstSeen.get(d.key);
			if (first) {
				earlier.set(d.key, first);
				d.alsoIn = first;
			} else {
				firstSeen.set(d.key, searchNo);
			}
			if (d.title) docText.set(d.key, d.title);
		}
		return { sp, out, earlier };
	}

	pi.registerTool({
		name: "prior_art_search",
		label: "Prior-art search (sealed)",
		description:
			"Search published patents for prior art related to a technical description. The description is sealed on " +
			"the user's machine to a search enclave that this machine verifies first; the user approves the first query " +
			"to each enclave. Returns references with publication numbers and titles, numbered as searches in this session, " +
			"noting documents an earlier search already returned. To cover one feature of the disclosure, search it on its " +
			"own and name it in `feature`. To find documents like a returned one, pass its publication number as `like` " +
			"(no text needed). `depth` sets how many references come back: quick 10, standard 25, broad 50. It surfaces " +
			"related art; it does not certify completeness or absence.",
		promptSnippet: "Search published patents for related prior art (sealed, user-approved)",
		promptGuidelines: [
			"Use prior_art_search when the user asks for prior art, related patents, or novelty context for a technical idea; pass a self-contained technical description of at least a few sentences.",
			"Do not describe prior_art_search results as proving novelty or the absence of prior art.",
		],
		// No cutoff parameter: the date bound is the matter's, held by the host verifier, not the model's to set.
		parameters: Type.Object({
			text: Type.Optional(Type.String({ description: "REQUIRED unless `like` is given: a self-contained technical description to search for (20 characters or more). `feature` only names the search; it is not searched." })),
			feature: Type.Optional(Type.String({ description: "A short name — a few words, under 80 characters — for the one feature of the disclosure this search covers; a longer one is shortened" })),
			like: Type.Optional(Type.String({ description: "A publication number returned by a search on this matter, in this session or an earlier one: search for documents like it" })),
			depth: Type.Optional(Type.String({ description: "How many references: quick 10 (default), standard 25, broad 50" })),
			k: Type.Optional(Type.Integer({ description: "Exact number of references to return, 1 to 50; overrides depth" })),
		}),

		async execute(_toolCallId, params, signal, onUpdate, ctx) {
			if (!ctx.hasUI) {
				throw new Error("prior_art_search needs the user at this machine to approve sealed queries; refused without sending anything");
			}
			// Which step the search is on, for the screen. A search normally takes about a second, so these
			// flash by; they earn their place when one step is slow or stuck — the page can then say WHICH step,
			// instead of "checking the search machine…" standing still while the real wait is elsewhere
			// (the approval prompt, or the reply). Phase names only: never the query, never a result.
			const phase = (name: string) => {
				try {
					onUpdate?.({ content: [], details: { phase: name } });
				} catch {
					/* progress is decoration; it must never break a search */
				}
			};
			// What to send, settled before anything is verified or sent.
			const like = String(params.like ?? "").trim().toUpperCase();
			let text = String(params.text ?? "").trim();
			if (like) {
				const known = docText.get(like) ?? priorDocs.get(like);
				if (!known) {
					throw new Error(`${like} was not returned by any search on this matter, so there is nothing to search like; nothing was sent`);
				}
				text = known;
			}
			if (text.length < 20) {
				throw new Error("prior_art_search needs a self-contained description of 20 characters or more, or `like` with a publication number a search on this matter returned; nothing was sent");
			}
			// The hints, normalised rather than refused (see the schema): a long label is cut at a word, an
			// unknown depth word means the default, and k is held to what the search machine serves (1-50).
			let feature = String(params.feature ?? "").replace(/\s+/g, " ").trim();
			if (feature.length > 80) {
				const cut = feature.slice(0, 79);
				feature = `${(cut.lastIndexOf(" ") > 40 ? cut.slice(0, cut.lastIndexOf(" ")) : cut).trimEnd()}…`;
			}
			const asked = params.k ?? DEPTH_K[String(params.depth ?? "quick").toLowerCase()] ?? 10;
			const k = Math.min(50, Math.max(1, Math.round(Number(asked) || 10)));
			const { sp, out, earlier } = await sealedSearch({ text, k, feature, like, ctx, signal, phase });
			const label = `Search ${searchNo}${feature ? ` (feature: ${feature})` : ""}${like ? ` (documents like ${like})` : ""}`;
			return { content: [{ type: "text", text: hitsText(out, label, earlier) }], details: sp };
		},

		renderResult(result, { expanded }, theme) {
			return renderSearchProof(result.details as SearchProof | undefined, expanded, theme);
		},
	});

	// ── the deep search: one press, a bounded fan-out, no model in the loop ────────────────────────
	//
	// Measured, on our own agent-loop experiments: the loop is good at REACHING (pool reachability
	// 0.27→0.41) and bad at JUDGING (its model-judge kept 0.062 of the keep-set). So this reaches widely
	// and judges nothing. The model chooses to call it and supplies the description, exactly as it does for
	// a single search; from that moment every sub-query is a deterministic function of that text and of the
	// professional's own marks. Nothing here reads a result and decides what to ask next — which is what
	// keeps the signed statements a record of what was searched rather than of something's opinion.
	//
	// The fan-out is bounded (DEEP_MAX) for two reasons that are not about cost: the sealed machine runs on
	// a schedule, and the page stops claiming the assistant is working after two minutes of complete
	// silence, so every sub-search must report and the whole press must stay inside the window.
	const DEEP_MAX = 8;
	const DEEP_WINDOW = 700;          // characters per window: long enough to be self-contained

	// Split into self-contained windows on sentence boundaries. A single long disclosure put as one query
	// is truncated upstream, and the tail — which is where the distinguishing features usually are — is
	// never searched at all.
	function deepWindows(text: string, max: number): string[] {
		const parts = text.split(/(?<=[.;:!?])\s+/).map((x) => x.trim()).filter(Boolean);
		const out: string[] = [];
		let cur = "";
		for (const part of parts) {
			if (cur && cur.length + part.length + 1 > DEEP_WINDOW) {
				out.push(cur);
				cur = "";
			}
			cur = cur ? `${cur} ${part}` : part;
		}
		if (cur) out.push(cur);
		const usable = out.filter((w) => w.length >= 20);
		if (usable.length <= max) return usable;
		// Spread the chosen windows ACROSS the text, always including the last one. Taking the first `max`
		// would search only the opening — which is the upstream truncation this leg exists to defeat, done
		// again by hand. The distinguishing features are usually near the end.
		const picked: string[] = [];
		for (let i = 0; i < max; i += 1) {
			picked.push(usable[Math.round((i * (usable.length - 1)) / (max - 1))]);
		}
		return [...new Set(picked)];
	}

	// Enumerated features, when the text has them ("1. …", "- …", "characterised in that …"). Searching one
	// feature on its own is the single cheapest way to reach art the whole-disclosure query never ranks.
	function deepElements(text: string, max: number): string[] {
		const out: string[] = [];
		for (const raw of text.split(/\n+/)) {
			const line = raw.replace(/^\s*(?:\d+[.)]|[-*•])\s+/, "").trim();
			if (line !== raw.trim() && line.length >= 20) out.push(line);
		}
		return out.slice(0, max);
	}

	// Features out of PROSE. deepElements only finds what an author numbered, and a disclosure written as
	// paragraphs has nothing numbered — so on the common case the fan-out was the whole text plus a window
	// or two, which is barely wider than one search. These are the sentences carrying a distinct technical
	// assertion, spread across the text rather than taken from the front, each searched on its own.
	// Deterministic: no model reads this, it is the same sentences every time for the same disclosure.
	function deepSentences(text: string, max: number): string[] {
		const parts = text.split(/(?<=[.;!?])\s+/)
			.map((x) => x.replace(/\s+/g, " ").trim())
			// Long enough to stand alone as a query, and carrying something a patent search can bite on.
			.filter((x) => x.length >= 60 && /\b(compris|configur|wherein|adapted|coupled|conne|generat|determin|measur|comput|receiv|transmit|approach|method|device|system|apparatus|module|layer|signal|circuit|sensor|model|key|enclave|index)/i.test(x));
		if (parts.length <= max) return parts;
		const picked: string[] = [];
		for (let i = 0; i < max; i += 1) picked.push(parts[Math.round((i * (parts.length - 1)) / (max - 1))]);
		return [...new Set(picked)];
	}

	// The subject of the disclosure, for anchoring short feature queries.
	//
	// A press on 24 Sep put "Pool bound commitment & epoch pinning" as a query on its own and the search
	// returned literal swimming pools. The feature was not wrong — it was a HEADING, and a heading torn out
	// of its document means whatever its words mean in general English. The fix is not cleverness: it is to
	// keep the subject attached, so "pool" is read in the sentence that says what this invention is.
	function deepAnchor(text: string): string {
		for (const raw of text.split(/\n+/)) {
			const line = raw.replace(/^[#>\s*-]+/, "").replace(/\s+/g, " ").trim();
			// The first line that is prose rather than a title: long enough to carry the subject, and not
			// itself a bare heading.
			if (line.length >= 40 && /[a-z]/.test(line)) return line.length > 180 ? `${line.slice(0, 179).trimEnd()}…` : line;
		}
		return "";
	}

	// `about` is what DISTINGUISHES this leg, which is not the same as the start of its query: once short
	// features carry the subject, every anchored query begins with the same sentence and a summary taken
	// from the front makes them all look identical — the very thing anchoring was added beside a fix for.
	interface DeepLeg { text: string; feature: string; like?: string; about?: string }

	// Which marks seed the walk. Only "relevant" — a document the professional set aside as known art or as
	// not relevant is not a seed, because walking outward from it would be the system quietly overruling the
	// judgement it asked them for. Named and exported to the same block as the planner so it can be tested:
	// inside the tool body this was a filter nothing could reach, and a test of the planner passed happily
	// while it said `true`.
	function relevantMarks(st: MatterMarks): string[] {
		return Object.entries(st.marks ?? {})
			.filter(([, m]) => m?.latest?.value === "relevant")
			.map(([k]) => k);
	}

	// The plan AND why it is the size it is. A press that put three queries when eight were allowed has a
	// reason — the disclosure has no numbered features, or nothing is marked yet — and that reason is the
	// most useful thing the professional can be told, because it is the thing they can change. Reporting
	// only the count invites the reading that the search gave up.
	interface DeepPlan { legs: DeepLeg[]; notes: string[] }

	// What a leg was actually about. `feature` is the CATEGORY and repeats — a press showed "one feature on
	// its own" twice and "part of the description" twice, with nothing to tell them apart, which is a list
	// that looks like a trace and carries none of one.
	function deepAbout(leg: DeepLeg): string {
		if (leg.like) return `documents like ${leg.like}`;
		const t = (leg.about || leg.text).replace(/\s+/g, " ").trim();
		return t.length > 72 ? `${t.slice(0, 71).trimEnd()}…` : t;
	}

	function deepPlan(text: string, relevant: string[]): DeepPlan {
		const legs: DeepLeg[] = [];
		const notes: string[] = [];
		const seen = new Set<string>();
		const add = (t: string, feature: string, like?: string, about?: string) => {
			const key = t.replace(/\s+/g, " ").trim().toLowerCase().slice(0, 200);
			if (!key || t.trim().length < 20 || seen.has(key) || legs.length >= DEEP_MAX) return false;
			seen.add(key);
			legs.push({ text: t.trim(), feature, like, about });
			return true;
		};
		// The whole description first: it is the query a single search would have made, so the deep search
		// can never return less than the plain one would have.
		add(text, "the disclosure as a whole");

		// Short features carry the subject with them; long ones already say what they are about. Without
		// this a heading like "Pool bound commitment" is searched as general English.
		const anchor = deepAnchor(text);
		const anchored = (f: string) => (anchor && f.length < 120 && !f.includes(anchor) ? `${anchor} ${f}` : f);

		const listed = deepElements(text, 3);
		let features = 0;
		for (const el of listed) if (add(anchored(el), "one feature on its own", undefined, el)) features += 1;
		if (!listed.length) {
			// Prose, not a numbered list. Sentences carrying a distinct technical assertion are searched on
			// their own instead — the same leg by another route, because an unnumbered disclosure is the
			// common case and was getting none of this.
			for (const st of deepSentences(text, 3)) if (add(anchored(st), "one feature on its own", undefined, st)) features += 1;
			notes.push(features
				? `${features} feature(s) taken from the text itself — it has no numbered or bulleted list, so they were read out of its sentences`
				: "no separable feature could be taken from the text: numbering the distinct features would let each be searched on its own");
		} else {
			notes.push(`${features} numbered feature(s) searched on their own`);
		}

		const windows = deepWindows(text, 3);
		let split = 0;
		for (const w of windows) if (add(w, "part of the description")) split += 1;
		notes.push(split > 1
			? `the description was long enough to split into ${split} overlapping parts, so its end was searched as well as its start`
			: "the description is short enough to fit one query, so it was not split");

		// The professional's own relevant marks, walked outward. Only documents they marked relevant, only
		// text an earlier search on this matter already returned — nothing new leaves because of this.
		let walked = 0;
		let unknown = 0;
		for (const key of relevant) {
			const known = docText.get(key) ?? priorDocs.get(key);
			if (!known) { unknown += 1; continue; }
			if (add(known, `like ${key}`, key)) walked += 1;
		}
		if (walked) notes.push(`${walked} document(s) you marked relevant were walked outward from`);
		else if (relevant.length) notes.push(`${relevant.length} document(s) are marked relevant, but this matter has not returned their text, so none could be walked outward from`);
		else notes.push("nothing is marked relevant yet — marking a document makes the next deep search walk outward from it");

		if (legs.length >= DEEP_MAX) notes.push(`stopped at the limit of ${DEEP_MAX} queries for one press`);
		return { legs, notes };
	}

	pi.registerTool({
		name: "deep_prior_art_search",
		label: "Deep prior-art search (sealed)",
		description:
			"Run a WIDE prior-art survey of a technical description in one step: it puts several sealed queries — the " +
			"description as a whole, individual features, parts of the text, and documents like the ones the professional " +
			"marked relevant — and returns the combined references. Use it when the professional asks for a deep, thorough " +
			"or autonomous search, or to open a matter that has had none. Prefer `prior_art_search` for a single targeted " +
			"question. Each sub-query is sealed and verified exactly as a single search is, and every one of them is " +
			"recorded. It surfaces related art; it does not certify completeness or absence.",
		promptSnippet: "Run a wide sealed prior-art survey in one step (several queries)",
		promptGuidelines: [
			"Use deep_prior_art_search when the professional asks to go deep, to survey thoroughly, or to search everything — pass the full technical description, not a summary.",
			"Do not describe its results as proving novelty or the absence of prior art.",
		],
		parameters: Type.Object({
			text: Type.String({ description: "The full technical description to survey — the disclosure itself where you have it, not a précis. Its features and parts become separate sealed queries." }),
		}),

		async execute(_toolCallId, params, signal, onUpdate, ctx) {
			if (!ctx.hasUI) {
				throw new Error("deep_prior_art_search needs the user at this machine to approve sealed queries; refused without sending anything");
			}
			// Position travels with the phase so a press that takes minutes does not look stalled: the page
			// repeats three phase names per sub-search otherwise, with nothing to say which one is running.
			let step = 0;
			let steps = 0;
			const phase = (name: string) => {
				try {
					onUpdate?.({ content: [], details: { phase: name, step, steps } });
				} catch {
					/* progress is decoration; it must never break a search */
				}
			};
			const text = String(params.text ?? "").trim();
			if (text.length < 20) {
				throw new Error("deep_prior_art_search needs a self-contained description of 20 characters or more; nothing was sent");
			}
			// The professional's marks, read from the host verifier — their judgements, not the model's.
			let relevant: string[] = [];
			try {
				relevant = relevantMarks((await searchCall("/matter/state", undefined, signal)) as unknown as MatterMarks);
			} catch {
				relevant = [];
			}
			const plan = deepPlan(text, relevant);
			const legs = plan.legs;
			const started = new Date().toISOString();
			const results: { feature: string; about: string; status: string; hits: number; searchNo?: number; why?: string }[] = [];
			const blocks: string[] = [];
			const union = new Map<string, { title: string; first: number }>();
			let sent = 0;
			let corpusId = "";

			steps = legs.length;
			for (const leg of legs) {
				step += 1;
				// Each sub-search re-emits the ordinary phases, so the page never goes quiet for two minutes
				// in the middle of a press. A phase name outside the fixed list is dropped before it reaches
				// the page, which would be progress reporting that reports nothing.
				let r: { sp: SearchProof; out: SearchVerdict; earlier: Map<string, number> };
				try {
					r = await sealedSearch({ text: leg.text, k: 10, feature: leg.feature, like: leg.like, ctx, signal, phase });
				} catch (err) {
					const why = err instanceof Error ? err.message : String(err);
					results.push({ feature: leg.feature, about: deepAbout(leg), status: "failed", hits: 0, why });
					// A declined approval or an unverifiable machine stops the whole press: every remaining
					// sub-query would ask the same machine the same question and fail the same way.
					if (/declined|did not verify|verifier did not answer/.test(why)) break;
					continue;
				}
				sent += 1;
				corpusId = corpusId || String(r.sp.index ?? "");
				const n = r.sp.searchNo ?? 0;
				results.push({ feature: leg.feature, about: deepAbout(leg), status: r.sp.docs.length ? "ok" : "empty",
				               hits: r.sp.docs.length, searchNo: n });
				for (const d of r.sp.docs) {
					if (!union.has(d.key)) union.set(d.key, { title: d.title ?? "", first: n });
				}
				blocks.push(hitsText(r.out, `Search ${n} — ${leg.feature}`, r.earlier));
			}

			disclosure.fanouts.push({
				at: started, planned: legs.length, cap: DEEP_MAX, sent,
				legs: results, documents: union.size, notes: plan.notes,
			});
			disclosure.write();

			if (!sent) {
				const why = results.find((x) => x.why)?.why ?? "no sub-query completed";
				throw new Error(`the deep search sent nothing: ${why}`);
			}
			const failed = results.filter((x) => x.status === "failed");
			const empty = results.filter((x) => x.status === "empty");
			const ledger = [
				`Deep search over ${corpusPhrase(corpusId)}: ${sent} of ${legs.length} sealed queries completed, `
					+ `${union.size} distinct documents.`,
				// WHY it was this size, in the professional's terms. Henry, 24 Sep, on being told only that
				// three queries ran: "why did it not search further… this can be improved to be clearer".
				// The count alone reads as the search giving up; the reasons are the part they can act on.
				`It put ${legs.length} of a possible ${DEEP_MAX}: ${plan.notes.join("; ")}.`,
				failed.length ? `${failed.length} did not complete (${failed.map((f) => f.feature).join("; ")}).` : "",
				empty.length ? `${empty.length} returned nothing (${empty.map((f) => f.feature).join("; ")}).` : "",
				// Permanent, not a placeholder: the family map that would collapse siblings lives on the
				// search side, and guessing family from publication numbers misses the cross-jurisdiction
				// siblings that are most of the duplication. Say it rather than let it look merged.
				"These are the combined results of separate queries, not a merged ranking: the same invention may appear more than once under different publication numbers.",
			].filter(Boolean).join(" ");

			return {
				content: [{ type: "text", text: `${ledger}\n\n${blocks.join("\n\n")}` }],
				// cap and notes travel HERE too. They were added to the session record only, so the page —
				// which reads `details` — rendered "a possible undefined" and an empty list of reasons.
				details: { deep: true, at: started, planned: legs.length, cap: DEEP_MAX, sent,
				           documents: union.size, legs: results, notes: plan.notes },
			};
		},

		renderResult(result, _options, theme) {
			const d = result.details as { sent?: number; planned?: number; documents?: number;
				legs?: { feature: string; status: string; hits: number }[] } | undefined;
			const box = new Box(1, 0, (t) => theme.bg("customMessageBg", t));
			if (!d) return box;
			box.addChild(new Text(theme.bold("Deep prior-art search")
				+ theme.fg("dim", `  ${d.sent ?? 0}/${d.planned ?? 0} queries · ${d.documents ?? 0} documents`), 0, 0));
			for (const leg of d.legs ?? []) {
				const mark = leg.status === "ok" ? "·" : leg.status === "empty" ? "–" : "✗";
				box.addChild(new Text(`  ${mark} ${leg.feature}${leg.status === "ok" ? ` (${leg.hits})` : ` — ${leg.status}`}`, 0, 0));
			}
			return box;
		},
	});

	// Relevance marks. A mark is a human judgement on a document, typed by the attorney — the model has no
	// way to reach the /matter/mark endpoint, so every mark is a human row. It is stored by the host verifier
	// in the matter state under confidential/ (write-denied to the agent), stamped there with actor=human and
	// the time; it is never written from the workspace. These become labels later, and only human marks are used.
	const MARK_LABEL: Record<string, string> = { relevant: "relevant", "not-relevant": "not relevant", known: "known art" };
	const PUB_RE = /^[A-Z]{2}[-A-Z0-9]{2,}$/;
	// The exposure of a marked document is computed HOST-SIDE by the verifier from what its searches opened;
	// the extension only reads it back to word the confirmation (M1).
	const EXPOSURE_NOTE: Record<string, string> = {
		this_session: "this session's search results",
		earlier_session: "an earlier session's search results",
		not_surfaced: "not surfaced by any search on this matter",
		unknown_prior: "not in this session's results (earlier sessions were not consulted)",
	};

	interface MarkEntry { value?: string; at?: string; surfaced?: string; rank?: number }
	interface MatterMarks { marks?: Record<string, { latest?: MarkEntry }> }

	function markCommand(value: "relevant" | "not-relevant" | "known") {
		return async (args: string, ctx: ExtensionContext) => {
			if (!ctx.hasUI) return;
			const raw = (args ?? "").trim();
			const key = raw.toUpperCase();
			if (!key) {
				ctx.ui.notify(`Usage: /${value} <publication-number>   e.g. /${value} US-7000-B2`, "error");
				return;
			}
			if (!PUB_RE.test(key)) {
				ctx.ui.notify(`"${raw}" is not a publication number. Mark a document by its number, e.g. /${value} US-7000-B2.`, "error");
				return;
			}
			let resp: MatterMarks;
			try {
				resp = (await searchCall("/matter/mark", { key, mark: value }, undefined)) as unknown as MatterMarks;
			} catch {
				ctx.ui.notify("could not record the mark: the local search verifier did not answer.", "error");
				return;
			}
			const latest = resp.marks?.[key]?.latest;
			const exposure = latest?.surfaced ? EXPOSURE_NOTE[latest.surfaced] ?? latest.surfaced : "";
			const rank = latest?.surfaced === "this_session" && latest.rank ? ` (rank ${latest.rank})` : "";
			ctx.ui.notify(
				`Marked ${key} as ${MARK_LABEL[value]}${exposure ? ` — ${exposure}${rank}` : ""}. ` +
					"Held with the matter on this machine, as your judgement.",
				"info",
			);
		};
	}

	pi.registerCommand("relevant", { description: "Mark a patent (by publication number) as relevant prior art", handler: markCommand("relevant") });
	pi.registerCommand("not-relevant", { description: "Mark a patent (by publication number) as not relevant", handler: markCommand("not-relevant") });
	pi.registerCommand("known", { description: "Mark a patent (by publication number) as known art", handler: markCommand("known") });

	pi.registerCommand("keep-warm", {
		description: "Keep the search enclave running (reset its idle countdown) and show the budget",
		handler: async (_args, ctx) => {
			if (!ctx.hasUI) return;
			const s = await lifecycleCall("/keep-warm", true);
			if (!s || !s.managed) {
				ctx.ui.notify("No managed enclave lifecycle this session — nothing to keep warm.", "info");
				return;
			}
			showLifecycle(ctx, s);
			ctx.ui.notify(
				[lifecycleLine(s), "Idle countdown reset.",
					"The enclave operator sees when your containers start and stop (timing and size), never their content."].join("\n"),
				"info",
			);
		},
	});

	pi.registerCommand("enclave", {
		description: "Show the search enclave's status: whether it is running, hours used, budget remaining",
		handler: async (_args, ctx) => {
			if (!ctx.hasUI) return;
			const s = await lifecycleCall("/lifecycle", false);
			if (!s || !s.managed) {
				ctx.ui.notify("No managed enclave lifecycle this session.", "info");
				return;
			}
			showLifecycle(ctx, s);
			const idle = typeof s.seconds_until_idle_reap === "number"
				? `\nReaps in ${Math.round(s.seconds_until_idle_reap / 60)} min if idle (use /keep-warm to hold it).` : "";
			ctx.ui.notify(
				[lifecycleLine(s), idle.trim(),
					"The operator sees when your containers start and stop (timing and size), never their content."].filter(Boolean).join("\n"),
				"info",
			);
		},
	});

	// The marks, handed over WITH the professional's message instead of fetched by a tool call. The contract asks
	// the assistant to read the marks before follow-up research; through `matter_marks` that is a tool round-trip,
	// so a second model request, every turn that uses them. Attached here, they ride in the request the
	// professional's own message already makes (Pi's before_agent_start: a context message in the same turn; the
	// pinned system prompt is untouched). Sent only when the marks changed since the last note — nothing repeats
	// or piles up — and with the candidate next steps, so the assistant can keep, reword, merge or drop them in
	// the suggestions it already makes at the end of its answer (Henry, 19 Sep: "improve, select or augment it
	// through the LLM without extra requests"). Never blocks a turn: any failure means no note.
	let lastMarksNote = "";
	pi.on("before_agent_start", async () => {
		if (!SEARCH) return;
		let state: MatterMarks;
		try {
			state = (await searchCall("/matter/state", undefined, AbortSignal.timeout(3000))) as unknown as MatterMarks;
		} catch {
			return;
		}
		const entries = Object.entries(state.marks ?? {})
			.map(([key, m]) => [key, String(m.latest?.value ?? "")] as const)
			.filter(([, v]) => v in MARK_LABEL)
			.sort(([a], [b]) => a.localeCompare(b));
		if (!entries.length) return;
		const signature = JSON.stringify(entries);
		if (signature === lastMarksNote) return;
		lastMarksNote = signature;
		const about = (key: string) => {
			const t = (docText.get(key) ?? priorDocs.get(key) ?? "").replace(/\s+/g, " ").trim();
			return t ? ` "${t.length > 70 ? `${t.slice(0, 69)}…` : t}"` : "";
		};
		const group = (v: string) => entries.filter(([, x]) => x === v).map(([k]) => `${k}${about(k)}`).join("; ");
		const relevant = entries.filter(([, v]) => v === "relevant").map(([k]) => k);
		// A new session is its own sitting: until it has run a search, running one is a candidate too.
		const candidates = [
			...(searchNo === 0 ? [STEP_SURVEY] : []),
			STEP_DEEP,
			...(relevant.length ? [STEP_DEEPER] : []),
			...relevant.slice(0, 2).map(stepLike),
			...(entries.some(([, v]) => v !== "relevant") ? [STEP_LEAVE_OUT] : []),
		];
		const text = [
			"[Probant note: the professional's relevance marks as of this message — their judgment, not yours. " +
				"Context for you, not a request: do not reply to it or mention it. It replaces any earlier marks note.]",
			...["relevant", "not-relevant", "known"].map((v) => (group(v) ? `Marked ${MARK_LABEL[v]}: ${group(v)}` : "")).filter(Boolean),
			`Next-step candidates from these marks: ${candidates.map((c) => `"${c}"`).join(" · ")}`,
			"When you call suggest_next_steps, treat these candidates as material: keep, reword (say what a document is " +
				"about), merge or drop them, and add your own — four at most in all.",
		].join("\n");
		return { message: { customType: "probant-marks", content: text, display: false } };
	});

	// The professional's marks, readable by the assistant so they can steer its research. Read-only: no tool or
	// endpoint the assistant can reach makes or changes a mark (those are typed or clicked by the professional).
	pi.registerTool({
		name: "matter_marks",
		label: "Your relevance marks",
		description:
			"Read the professional's relevance marks for this matter: which returned documents they marked relevant, not " +
			"relevant, or known, and whether a search in this matter returned them. Read-only. Marks are the professional's " +
			"judgment; use them to steer follow-up searches, report them as theirs, and never adopt them as your own conclusion.",
		promptSnippet: "Read the professional's relevance marks (read-only)",
		parameters: Type.Object({}),
		async execute(_toolCallId, _params, signal) {
			let state: MatterMarks;
			try {
				state = (await searchCall("/matter/state", undefined, signal)) as unknown as MatterMarks;
			} catch {
				throw new Error("the local search verifier did not answer; the marks could not be read");
			}
			const entries = Object.entries(state.marks ?? {});
			const lines = entries.map(([key, m]) => {
				const l = m.latest ?? {};
				const exp = l.surfaced ? `; ${EXPOSURE_NOTE[l.surfaced] ?? l.surfaced}${l.surfaced === "this_session" && l.rank ? `, rank ${l.rank}` : ""}` : "";
				return `- ${key}: ${MARK_LABEL[String(l.value)] ?? l.value}${exp}`;
			});
			const text = entries.length
				? ["The professional's relevance marks for this matter (their judgment, not yours):", ...lines].join("\n")
				: "The professional has not marked any document on this matter yet.";
			return { content: [{ type: "text", text }], details: { count: entries.length } };
		},
		renderResult(result, _options, theme) {
			const n = Number((result.details as { count?: number } | undefined)?.count ?? 0);
			const box = new Box(1, 0, (t) => theme.bg("customMessageBg", t));
			box.addChild(new Text(theme.fg("dim", `Read your relevance marks (${n})`), 0, 0));
			return box;
		},
	});

	pi.registerTool({
		name: "suggest_next_steps",
		label: "Next steps",
		description:
			"Offer the professional two to four next research actions they can send with one click, exactly as written. " +
			"Call it last in an answer that reports or discusses search results — and also after any other answer from which a " +
			"research action naturally follows (after summarising the disclosure: running the survey) — and write nothing " +
			"after it. Write each step in " +
			"the professional's own words, as they would ask you (\"Find documents like US-5795305-A\", \"Use my marks to steer " +
			"the next searches\"), with no tool or parameter names: a follow-up research action within your tools, never a " +
			"judgment and never a command. Keep each to one sentence, ideally under 160 characters: it is shown and sent " +
			"in full. When a Probant note lists next-step candidates from the professional's marks, use them as material: " +
			"keep, reword, merge or drop them, and add your own. Never mention this tool or the steps in your written answer.",
		promptSnippet: "Offer the professional one-click next research steps (call last)",
		parameters: Type.Object({
			steps: Type.Array(Type.String(), { minItems: 1 }),
		}),
		async execute(_toolCallId, params) {
			const steps = cleanSteps(params.steps);
			lastSteps = steps;
			return {
				// A neutral acknowledgement: anything that reads as an instruction ("end your answer here") gets
				// answered in the transcript, as the model once did with "(no further output follows …)".
				content: [{ type: "text", text: steps.length
					? "Done: the professional sees these as buttons under your answer. Your answer is complete — end your turn with no further text, and do not refer to the steps or the buttons."
					: "No usable steps were given." }],
				details: { steps },
			};
		},
		renderResult(result, _options, theme) {
			const steps = ((result.details as { steps?: string[] } | undefined)?.steps ?? []);
			const box = new Box(1, 0, (t) => theme.bg("customMessageBg", t));
			if (!steps.length) return box;
			box.addChild(new Text(theme.bold("Next steps") + theme.fg("dim", "  · send one with /next <number>"), 0, 0));
			steps.forEach((st, i) => box.addChild(new Text(`  ${i + 1}. ${st}`, 0, 0)));
			return box;
		},
	});

	pi.registerCommand("next", {
		description: "Send one of the suggested next steps as your message: /next 1",
		handler: async (args, ctx) => {
			const n = Number(String(args ?? "").trim());
			const step = Number.isInteger(n) ? lastSteps[n - 1] : undefined;
			if (!step) {
				if (ctx.hasUI) {
					ctx.ui.notify(lastSteps.length ? `Choose a step from 1 to ${lastSteps.length}, e.g. /next 1` : "No next steps have been suggested yet.", "info");
				}
				return;
			}
			try {
				pi.sendUserMessage(step);
			} catch {
				pi.sendUserMessage(step, { deliverAs: "followUp" });
			}
		},
	});

	pi.registerCommand("marks", {
		description: "List this matter's relevance marks (held on this machine, your judgements)",
		handler: async (_args, ctx) => {
			if (!ctx.hasUI) return;
			let state: MatterMarks = {};
			try {
				state = (await searchCall("/matter/state", undefined, undefined)) as unknown as MatterMarks;
			} catch {
				ctx.ui.notify("could not read the matter's marks: the local search verifier did not answer.", "error");
				return;
			}
			const entries = Object.entries(state.marks ?? {});
			if (!entries.length) {
				ctx.ui.notify("No relevance marks yet. Mark a document with /relevant, /not-relevant or /known.", "info");
				return;
			}
			const lines = entries.map(([k, m]) => {
				const l = m.latest ?? {};
				const exp = l.surfaced ? ` · ${EXPOSURE_NOTE[l.surfaced] ?? l.surfaced}` : "";
				return `  ${k}: ${MARK_LABEL[String(l.value)] ?? l.value}${l.at ? ` · ${l.at}` : ""}${exp}`;
			});
			ctx.ui.notify(["Relevance marks for this matter (your judgements, held on this machine):", ...lines].join("\n"), "info");
		},
	});
}
