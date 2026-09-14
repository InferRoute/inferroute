/**
 * ir attested session for Pi.
 *
 * Shows the user what this machine verified about the model enclave, in Pi's own UI: a footer status
 * for the whole session and a proof card in the transcript. Both are read from ir's local sealed
 * endpoint, never from anything the model produced, and neither is sent to the model (the card is a
 * custom entry, which Pi keeps out of model context).
 *
 * Refuses to send a model request unless the session is verified and the request is addressed to
 * this session's local sealed endpoint. Tools outside the launch allowlist are refused.
 */
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Box, Text } from "@earendil-works/pi-tui";

const ENDPOINT = (process.env.IR_ATTESTED_ENDPOINT ?? "").replace(/\/+$/, "");
const PROVIDER = process.env.IR_ATTESTED_PROVIDER ?? "inferroute";
const TOOLS = new Set((process.env.IR_ATTESTED_TOOLS ?? "").split(",").map((t) => t.trim()).filter(Boolean));
const STATUS_KEY = "ir-model-enclave";
const PROOF_ENTRY = "ir-attested-proof";
const REFRESH_MS = 30_000;

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
	ctx.ui.setStatus(STATUS_KEY, theme.fg(v.ok ? "success" : "error", statusText(v)));
}

function refuse(ctx: ExtensionContext, why: string): void {
	const msg = `Model request blocked: ${why}`;
	if (ctx.hasUI) ctx.ui.notify(msg, "error");
	else process.stderr.write(`${msg}\n`);
	ctx.abort();
}

export default function (pi: ExtensionAPI) {
	let timer: ReturnType<typeof setInterval> | undefined;

	pi.registerEntryRenderer<Verdict>(PROOF_ENTRY, (entry, { expanded }, theme) => {
		const box = new Box(1, 1, (t) => theme.bg("customMessageBg", t));
		const v = entry.data;
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
	});

	async function record(ctx: ExtensionContext): Promise<Verdict> {
		const v = await readVerdict();
		showStatus(ctx, v);
		pi.appendEntry<Verdict>(PROOF_ENTRY, v);
		return v;
	}

	pi.on("session_start", async (_event, ctx) => {
		if (TOOLS.size) pi.setActiveTools(pi.getActiveTools().filter((t) => TOOLS.has(t)));
		await record(ctx);
		if (timer) clearInterval(timer);
		timer = setInterval(async () => showStatus(ctx, await readVerdict()), REFRESH_MS);
		timer.unref?.();
	});

	pi.on("session_shutdown", async () => {
		if (timer) clearInterval(timer);
		timer = undefined;
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
}
