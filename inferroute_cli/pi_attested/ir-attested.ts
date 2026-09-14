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
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ENDPOINT = (process.env.IR_ATTESTED_ENDPOINT ?? "").replace(/\/+$/, "");
const SEARCH = (process.env.IR_SEARCH_ENDPOINT ?? "").replace(/\/+$/, "");
const PROVIDER = process.env.IR_ATTESTED_PROVIDER ?? "inferroute";
const TOOLS = new Set((process.env.IR_ATTESTED_TOOLS ?? "").split(",").map((t) => t.trim()).filter(Boolean));
const STATUS_KEY = "ir-model-enclave";
const SEARCH_STATUS_KEY = "ir-search-enclave";
const PROOF_ENTRY = "ir-attested-proof";
const SEARCH_PROOF_ENTRY = "ir-search-proof";
const REFRESH_MS = 30_000;
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
		const res = await fetch(`${ENDPOINT}/confidential/receipt`, { signal: AbortSignal.timeout(5_000) });
		if (!res.ok) return unverified(`the local sealed endpoint answered ${res.status}`);
		return verdictOf((await res.json()) as Receipt);
	} catch {
		return unverified("the local sealed endpoint did not answer");
	}
}

function statusText(v: Verdict): string {
	if (!v.ok) return `⛔ model enclave not verified: model requests blocked (${v.reason})`;
	return `🔒 model enclave verified ${v.verifiedAt.slice(11, 16)}Z · ${v.passed}/${v.total} checks · sealed on this machine`;
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
		? theme.fg("success", theme.bold(`🔒 Model enclave verified by this machine at ${v.verifiedAt}`))
		: theme.fg("error", theme.bold(`⛔ Model enclave NOT verified: ${v.reason}. Model requests are blocked.`)));
	line(theme.fg("dim", "Read from ir's local endpoint on this machine, not from the model. Not sent to the model."));
	if (v.model) line(`${theme.fg("muted", "model    ")} ${v.model}${v.gpus ? ` · ${v.gpus} GPUs` : ""}${v.instance ? ` · instance ${v.instance}` : ""}`);
	if (v.sealing) line(`${theme.fg("muted", "sealing  ")} ${v.sealing}, keys made on this machine`);
	if (v.transport) line(`${theme.fg("muted", "carrier  ")} ${v.transport}`);
	if (v.total) {
		line(`${theme.fg("muted", "checks   ")} ${v.passed}/${v.total} passed${expanded ? "" : " (expand to list)"}`);
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
	phase: "verify" | "search" | "declined";
	steps: SearchStep[];
	measurement: string;
	policy: string;
	index: string;
	enclaveKey: string;
	hits: number;
	at: string;
}

function searchProofOf(out: SearchVerdict, phase: SearchProof["phase"]): SearchProof {
	return {
		ok: out.ok && phase !== "declined",
		refusal: phase === "declined" ? "the user declined to send a sealed query" : String(out.refusal ?? ""),
		testRoots: out.test_roots === true,
		phase,
		steps: out.steps ?? [],
		measurement: String(out.enclave?.measurement ?? ""),
		policy: String(out.enclave?.host_data ?? ""),
		index: String(out.enclave?.index_snapshot ?? ""),
		enclaveKey: String(out.enclave?.enclave_key ?? ""),
		hits: Number(out.statement?.hits_n ?? 0),
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

function searchStatus(ctx: ExtensionContext, p: SearchProof): void {
	if (!ctx.hasUI) return;
	const t = ctx.ui.theme;
	const passed = p.steps.filter((s) => s.ok).length;
	const text = p.ok
		? `🔒 search enclave verified${p.testRoots ? " (TEST ROOTS)" : ""} · policy ${p.policy.slice(0, 8)}… · ${passed}/${p.steps.length} checks`
		: `⛔ search enclave: ${p.refusal}`;
	ctx.ui.setStatus(SEARCH_STATUS_KEY, t ? t.fg(p.ok && !p.testRoots ? "success" : p.ok ? "warning" : "error", text) : text);
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
			? `🔒 Sealed prior-art search: enclave verified by this machine, ${p.hits} results opened here`
			: "🔒 Search enclave verified by this machine")));
	} else {
		line(theme.fg("error", theme.bold(`⛔ Sealed prior-art search refused: ${p.refusal}`)));
	}
	if (p.testRoots) line(theme.fg("warning", theme.bold("TEST ROOTS PINNED: this is a test enclave, not a production one")));
	line(theme.fg("dim", "Checked by the local search verifier on this machine, not by the model. Not sent to the model."));
	if (p.measurement) line(`${theme.fg("muted", "utility VM ")} ${p.measurement.slice(0, 24)}…`);
	if (p.policy) line(`${theme.fg("muted", "policy     ")} ${p.policy.slice(0, 24)}…`);
	if (p.index) line(`${theme.fg("muted", "index      ")} ${p.index}`);
	if (p.enclaveKey) line(`${theme.fg("muted", "sealed to  ")} ${p.enclaveKey}…`);
	line(`${theme.fg("muted", "checks     ")} ${passed}/${p.steps.length} passed${expanded ? "" : " (expand to list)"}`);
	for (const s of p.steps) {
		if (!expanded && s.ok) continue;
		line(`  ${s.ok ? theme.fg("success", "✓") : theme.fg("error", "✗")} ${s.step}${expanded ? theme.fg("dim", ` · ${s.detail}`) : ""}`);
	}
	return box;
}

function hitsText(out: SearchVerdict): string {
	const hits = out.result?.hits ?? [];
	const lines = [
		`${hits.length} references surfaced by a sealed search over ${out.enclave?.index_snapshot ?? "the index"}. ` +
		`${out.result?.claim_boundary ?? "It surfaces related art; it does not certify completeness or absence."}`,
	];
	hits.forEach((h, i) => lines.push(`${i + 1}. ${h.key}${h.year ? ` (${h.year})` : ""}${h.title ? ` ${h.title}` : ""}`));
	return lines.join("\n");
}

// ───────────────────────── the extension ─────────────────────────

// ───────────────────────── per-session disclosure record ─────────────────────────
//
// The spine of the product, stated for one session: which surface saw what. Written to
// INFERROUTE_HOME/confidential/attested-sessions/<session>.json on shutdown and after each search.

const HOME = process.env.INFERROUTE_HOME ?? "";
const CONFINED = (process.env.IR_ATTESTED_CONFINE ?? "").trim().toLowerCase() !== "off";

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
	searchOffered = false;
	searches: SearchRecord[] = [];

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
			started_at: this.startedAt,
			written_at: new Date().toISOString(),
			model_lane: { verified: this.modelOk, checks: this.modelChecks, receipt: this.modelReceipt },
			search_lane: { offered: this.searchOffered, searches: this.searches },
			which_surface_saw_what: this.surfaces(),
			note: "A per-surface disclosure record for one attested session. Each line is a checked fact, not a promise.",
		};
	}

	write(): string | null {
		if (!HOME || !this.sessionId) return null;
		try {
			const dir = join(HOME, "confidential", "attested-sessions");
			mkdirSync(dir, { recursive: true });
			const path = join(dir, `${this.sessionId}.json`);
			writeFileSync(path, `${JSON.stringify(this.toJSON(), null, 1)}\n`);
			return path;
		} catch {
			return null;
		}
	}
}

export default function (pi: ExtensionAPI) {
	let timer: ReturnType<typeof setInterval> | undefined;
	const approved = new Set<string>();
	const disclosure = new SessionRecord();

	pi.registerEntryRenderer<Verdict>(PROOF_ENTRY, (entry, { expanded }, theme) => renderModelProof(entry.data, expanded, theme));
	pi.registerEntryRenderer<SearchProof>(SEARCH_PROOF_ENTRY, (entry, { expanded }, theme) => renderSearchProof(entry.data, expanded, theme));

	async function record(ctx: ExtensionContext): Promise<Verdict> {
		const v = await readVerdict();
		showStatus(ctx, v);
		pi.appendEntry<Verdict>(PROOF_ENTRY, v);
		disclosure.modelOk = v.ok;
		disclosure.modelChecks = v.total ? `${v.passed}/${v.total}` : "";
		disclosure.modelReceipt = v.receiptPath;
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
		await record(ctx);
		if (SEARCH && ctx.hasUI) {
			const t = ctx.ui.theme;
			const text = "search enclave: verified before the first sealed query";
			ctx.ui.setStatus(SEARCH_STATUS_KEY, t ? t.fg("dim", text) : text);
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

	if (!SEARCH) return;

	pi.registerTool({
		name: "prior_art_search",
		label: "Prior-art search (sealed)",
		description:
			"Search published patents for prior art related to a technical description. The description is sealed on " +
			"the user's machine to a search enclave that this machine verifies first; the user approves the first query " +
			"to each enclave. Returns references with publication numbers and titles. It surfaces related art; it does " +
			"not certify completeness or absence.",
		promptSnippet: "Search published patents for related prior art (sealed, user-approved)",
		promptGuidelines: [
			"Use prior_art_search when the user asks for prior art, related patents, or novelty context for a technical idea; pass a self-contained technical description of at least a few sentences.",
			"Do not describe prior_art_search results as proving novelty or the absence of prior art.",
		],
		parameters: Type.Object({
			text: Type.String({ description: "A self-contained technical description to search for (20 characters or more)" }),
			k: Type.Optional(Type.Integer({ minimum: 1, maximum: 50, description: "How many references to return (default 10)" })),
			cutoff_date: Type.Optional(Type.Integer({ description: "Only art published before this date, as YYYYMMDD" })),
		}),

		async execute(_toolCallId, params, signal, _onUpdate, ctx) {
			if (!ctx.hasUI) {
				throw new Error("prior_art_search needs the user at this machine to approve sealed queries; refused without sending anything");
			}
			let verified: SearchVerdict;
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
			const key = `${e.lifetime_id}|${e.host_data}|${e.measurement}`;
			if (!approved.has(key)) {
				const ok = await ctx.ui.confirm(
					"Send a sealed prior-art query?",
					[
						vp.testRoots ? "TEST ROOTS PINNED: this is a test enclave, not a production one.\n" : "",
						"This machine verified the search enclave: AMD SEV-SNP hardware, the utility VM Microsoft endorses, ",
						"and the container policy this client pins.\n",
						`  utility VM   ${String(e.measurement ?? "").slice(0, 24)}…\n`,
						`  policy       ${String(e.host_data ?? "").slice(0, 24)}…\n`,
						`  index        ${e.index_snapshot ?? ""}\n`,
						`  enclave key  ${e.enclave_key ?? ""}…\n`,
						"The model's search text will be sealed here to that key. The host sees its size and timing, not its words. ",
						"Approve queries to this enclave for this session?",
					].join(""),
				);
				if (!ok) {
					pi.appendEntry<SearchProof>(SEARCH_PROOF_ENTRY, searchProofOf(verified, "declined"));
					throw new Error("the user declined to send a sealed query to the search enclave; nothing was sent");
				}
				approved.add(key);
			}
			let out: SearchVerdict;
			try {
				out = await searchCall("/search", {
					text: params.text, k: params.k ?? 10, cutoff_date: params.cutoff_date ?? null, expect_lifetime_id: e.lifetime_id,
				}, signal);
			} catch {
				throw new Error("the local search verifier did not answer; the search did not complete");
			}
			const sp = searchProofOf(out, "search");
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
			return { content: [{ type: "text", text: hitsText(out) }], details: sp };
		},

		renderResult(result, { expanded }, theme) {
			return renderSearchProof(result.details as SearchProof | undefined, expanded, theme);
		},
	});
}
