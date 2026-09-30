# Adding a host must force the question "how can this one be routed away?"

**Four of our six adapters have never been asked.** That is the finding, and everything below is
scaffolding for it.

**Status: design note. Nothing here is scheduled before the Bétrancourt delivery, and none of it is
promised in the delivery report — the report makes no neutrality claim, deliberately, because today one
would be a promise about five adapters whose routing surfaces nobody has enumerated.**

Raised by Henry, 2026-09-30: *"I don't think we can rely on Claude Code skills since ir should eventually
be coding-agent neutral."*

## What is already true, measured rather than assumed

Three things were believed about our coupling that turned out to be wrong, so they are recorded before
the proposal:

* **The client-facing product is not Claude Code.** `ir probant open` launches `agent="pi"`
  (probant.py:349/383/1109). The Claude-specific machinery — `ANTHROPIC_BASE_URL`, the `--settings`
  precedence layer, `CLAUDE_CODE_USE_*` — is confined to the `agent == "claude"` branch. Nothing a client
  touches depends on Claude Code.
* **The per-host adapter split is the current shape, not a proposal.** Six adapters exist: claude, pi,
  opencode, goose, openhands, codewhale, each with its own `*_env_argv`.
* **`pi` is the strongest implementation of the invariant we have, not the coupled part.** It enforces at
  three layers: config isolation (a fresh `PI_CODING_AGENT_DIR` declaring one provider — the settings-file
  route that made the Claude bypass hard to close *structurally cannot exist*), launch refusal
  (`REFUSED_FLAGS` rejects `--provider`, `--api-key`, `--models`, `--tools`, `-e`, transcript resume, each
  with a reason, **before** verifying), and **request-time refusal**: the extension refuses any model
  request not addressed to this session's endpoint, or sent while the verdict is anything but verified.

## The invariant

> A session's model traffic reaches the sealed route, or the panel does not render.

Enforced **at request time** by the adapter, with launch-time neutralisation as defence in depth. `pi`
does both. `claude` does only the second, even after the 2026-09-30 bypass fix — that gap is the first
item in the queue below, above anything cosmetic.

## The part worth building: a declaration, not an abstraction

Each adapter must **declare** its host's routing surfaces. The value is not the abstraction — it is that
a new adapter cannot be added without someone answering the question, which is the question nobody asked
about Claude Code until an external audit asked it for us.

Mandatory fields, each one drawn from a surface that has actually bitten us or Pi:

| field | why it is mandatory |
|---|---|
| provider selection | `CLAUDE_CODE_USE_BEDROCK/VERTEX/MANTLE` beat our base URL; the 2026-09-12 bypass |
| settings precedence | `/setup-bedrock` writes to a settings file a child-env strip cannot reach |
| proxy variables | **host-neutral**: the sealed proxy is a loopback hop for every agent, so `HTTP_PROXY` can receive the plaintext. Only Pi handled it until 2026-09-30 |
| extension / plugin loading | user extensions loading into a process that holds plaintext |
| transcript resume | a persisted transcript can be edited and re-injected |
| request-time hook | whether the host lets us refuse a mis-addressed request at all — the strongest layer, and the one that decides whether the invariant is enforceable or merely attempted |

The proxy row is the evidence that this works: nobody set out to look for it. It surfaced because
enumerating Pi's protections against the others made the asymmetry visible, and it had been open in five
adapters for as long as they had existed.

## Queue

1. **A request-time layer for the `claude` adapter**, closing the one-layer gap with `pi`. Above cosmetics.
2. Write the declarations for the four never-examined adapters (opencode, goose, openhands, codewhale),
   which is also the honest precondition for claiming any neutrality publicly.
3. MCP as the seam for *tools* (`sealed_search` as an MCP server runs in any MCP-capable host). Note this
   is a smaller claim than neutrality of the whole launcher, and should not be conflated with it.

## What does not need doing

Nothing Bétrancourt-facing prefers a Claude Code skill over a host-neutral form today, because that path
runs Pi. The near-term discipline is only that **new** client features should not deepen Claude-specific
coupling where a host-neutral form exists.
