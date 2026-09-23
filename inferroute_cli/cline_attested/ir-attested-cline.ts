/**
 * InferRoute's Cline plugin: refuse to send when the session is not sealed.
 *
 * Cline is the only agent besides Pi with a pre-request hook, so it is the only other one where we can
 * VETO rather than only show. What we cannot do is write Cline's provider config — the published `cline`
 * package carries CLINE_DIR, CLINE_DATA_DIR, CLINE_BIN_PATH and no base-URL or provider variable, and the
 * OpenAI-compatible provider is a settings-panel form. So the division of labour is: the person points
 * Cline at the sealed endpoint (`ir cline` prints the two values), and this plugin makes sure that is
 * where the traffic actually goes — refusing every model request while it is not.
 *
 * FIELD NAMES ARE FROM THE SOURCE, NOT THE DOCS. @cline/core 0.0.85 reads `stop === true` off a hook
 * result and takes the reason from `cancelReason`. The plugin guide says `{ stop: true, reason }` and the
 * blog post says `{ skip: true, reason }` — the blog is wrong, and a veto returning the wrong key would
 * look like enforcement and do nothing at all.
 */
const ENDPOINT = (process.env.IR_ATTESTED_ENDPOINT ?? "").replace(/\/+$/, "");
const KEY = process.env.IR_ATTESTED_KEY ?? "";
const RECHECK_MS = 30_000;

let cached: { at: number; why: string | null } = { at: 0, why: "not checked yet" };

/** A refusal reason, or null when this session may send. Never throws: an error IS a refusal. */
async function refusal(): Promise<string | null> {
	if (!ENDPOINT) return "this session was not given a sealed endpoint";
	const now = Date.now();
	if (now - cached.at < RECHECK_MS) return cached.why;
	let why: string | null;
	try {
		const res = await fetch(`${ENDPOINT}/confidential/receipt`, {
			headers: KEY ? { authorization: `Bearer ${KEY}` } : {},
			signal: AbortSignal.timeout(5_000),
		});
		if (!res.ok) {
			// 401 means this is not our endpoint or not our key; 503 means the session has stopped being
			// confidential. Either way it is not somewhere a prompt should go.
			why = `the sealed endpoint answered ${res.status}`;
		} else {
			const r: any = await res.json();
			why = r?.verdict === "confidential"
				? null
				: `the confidential session is ${r?.verdict ?? "in an unknown state"}${r?.refusal ? `: ${r.refusal}` : ""}`;
		}
	} catch {
		why = "the sealed endpoint could not be reached";
	}
	cached = { at: now, why };
	return why;
}

const plugin = {
	name: "inferroute-attested",
	manifest: { capabilities: ["hooks"] },
	setup() {
		/* nothing to register: this plugin only refuses */
	},
	hooks: {
		beforeModel: async () => {
			const why = await refusal();
			return why ? { stop: true, cancelReason: `InferRoute: not sending — ${why}` } : undefined;
		},
	},
};

export default plugin;
