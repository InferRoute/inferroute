# Document readings in 0.9.97

Read document creates draft matters under the client selected before starting. The agent reads the complete source and calls `create_draft_matter` for each distinct invention. It has read-only file tools and no search tool.

The host binds the tool to that source and client, checks a supporting passage against its protected source snapshot, assigns an unused matter name, and saves the complete technical summary and source provenance. Summaries above 20,000 characters are refused explicitly rather than clipped. Existing matters are never overwritten. Creation is serialized with manual creation; a protected journal makes repeated calls recoverable after interruption.

Draft matters appear in the session and home. Review the disclosure and date before searching or sharing. An AI-suggested date is not applied until review. The host enforces this review requirement in the session launcher and sharing export. Matching a passage establishes its presence in the source, not the accuracy or completeness of the AI summary.

Recent readings remain accessible from home. Sessions are matched by unique upload ID, so simultaneous uploads with the same filename cannot reuse another document’s session or destination client. Legacy proposals retain complete summaries and can still be imported manually. CLI document readings accept `--client`; `--proposals-only` retains the earlier workflow.

Validation for this change: Python and JavaScript syntax checks, TypeScript transpilation, wheel build and package-content inspection. No automated test suite or live AI reading was run for this change.

The session page encodes `client/matter` as one route segment when opening a draft in home, so clients and matter names both survive the link.
