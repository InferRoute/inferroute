"""The deliverable: a prior-art search report a European patent attorney can put in a client file.

Shaped after EPO Form 1503 and the PCT/ISA/210 search report, because that is the document this reader
already knows how to scan — the same columns in the same order, the same citation conventions.

ONE DELIBERATE DIFFERENCE, and it is the point of the product. Form 1503 carries an X/Y/A category per
citation. The EPO's own Guidelines (B-III 1.1) say those categories "amount to implicit opinions on
patentability". A machine that printed an X would be asserting that a claim is not new. This report
prints no category. What it prints instead is a fact: for each document, the passage nearest to each
part of the disclosure, with the distance that produced it. Where an examiner writes a judgment, this
writes a measurement and leaves the judgment to the reader.

Everything here is derived from the signed statement and the sealed result. Nothing is asserted that
the pipeline did not measure.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .certificate import _CSS, _esc

_REPORT_CSS = _CSS + """
.secthead{font-size:1rem;margin:1.4rem 0 .3rem;padding-bottom:.2rem;border-bottom:1px solid #ddd}
.rpt h2 { border-bottom: 1px solid #999; padding-bottom: 2px; margin-top: 1.6em; }
.cite { margin: 0 0 1.1em 0; padding-left: 2.6em; text-indent: -2.6em; }
.cite .id { font-weight: bold; }
.cite .legs { color: #555; font-size: 90%; }
.psg { margin: .35em 0 0 2.6em; padding-left: .7em; border-left: 2px solid #ccc; color: #333; font-size: 93%; }
.scope td, .scope th { font-size: 93%; }
.limit { background: #f6f6f2; border: 1px solid #ddd; padding: .8em 1em; margin-top: 1.4em; }
.muted { color: #666; }
"""


# A tag is `<` IMMEDIATELY followed by a name. The first pattern, `<[^>]{1,80}>`, also matched
# "< B and C >" and so deleted words from "A < B and C > D" -- patent text in chemistry and
# mathematics is full of comparisons, and a claim with its inequality removed says something else.
_TAG = re.compile(r"</?[A-Za-z][A-Za-z0-9:-]*(?:\s[^<>]{0,200})?/?>")


def _clean(v: Any) -> str:
    """Source metadata is not trusted to be plain text. OpenAlex titles arrive wrapped in <title> tags
    and sprinkled with JATS markup; a patent title can carry entities. Strip tags before escaping, or
    the report shows the reader angle brackets and calls it a title."""
    import html as _html
    return " ".join(_TAG.sub(" ", _html.unescape(_html.unescape(str(v or "")))).split())


def _fmt_date(d: Any) -> str:
    s = str(d or "")
    return f"{s[:4]}-{s[4:6]}-{s[6:8]}" if len(s) == 8 and s.isdigit() else (s or "—")


def _identifier(h: Dict[str, Any]) -> str:
    """What a reader would write down to go and find this document.

    For a patent, the publication number. For a paper, the DOI if one exists — a database URL is not a
    citation, and an attorney copying "https://openalex.org/W4413205434" into a file has recorded the
    row we happened to retrieve rather than the work itself."""
    if h.get("source") == "patent":
        return _clean(h.get("key"))
    doi = _clean(h.get("doi"))
    if doi:
        return doi if doi.startswith("http") else f"https://doi.org/{doi}"
    return _clean(h.get("key"))


def _citation_line(h: Dict[str, Any], n: int) -> str:
    """ST.14-flavoured: identifier, date, title, and for literature the venue. No category letter, by
    design — that is the judgment this report does not make."""
    key = _identifier(h)
    src = h.get("source", "paper")
    date = _fmt_date(h.get("date")) if h.get("date") else (str(h.get("year")) if h.get("year") else "undated in this index")
    venue = _clean(h.get("venue"))
    title = _esc(_clean(h.get("title")) or "(no title in this index)")
    if venue and src != "patent":
        title = f"{title} <i>{_esc(venue)}</i>"
    legs = ", ".join(h.get("legs") or [])
    also = h.get("family_also") or []
    fam = ("" if not also else
           '<br><span class="muted">&nbsp;&nbsp;&nbsp;&nbsp;same patent family, also surfaced: '
           + ", ".join(_esc(m["key"]) for m in also) + "</span>")
    kind = "patent document" if src == "patent" else "scientific publication"
    return (f'<p class="cite"><span class="id">D{n}</span>&nbsp;&nbsp;{_esc(key)} — {title} '
            f'<span class="muted">[{kind}; {date}]</span> '
            f'<span class="legs">surfaced by: {_esc(legs)}; score {h.get("score", 0):.3f}</span>{fam}</p>')


def _passages(h: Dict[str, Any]) -> str:
    """The measured part: nearest passage per aspect of the disclosure, when the pipeline computed them."""
    ps = h.get("passages") or []
    if not ps:
        return ""
    # Where the passage was measured is part of the evidence: a description quote and an abstract quote
    # are not the same kind of fact, and the reader must not have to guess which one this is.
    where = "in the description" if h.get("passage_source") == "description" else "in the abstract"
    out = []
    for p in ps[:4]:
        asp = _esc(_clean(p.get("aspect")))[:110]
        txt = _esc(_clean(p.get("text")))[:320]
        body = f"{txt}…" if txt else '<i class="muted">[passage text withheld — see note below]</i>'
        out.append(f'<div class="psg"><b>nearest to:</b> "{asp}…" &nbsp;'
                   f'<span class="muted">(cosine {p.get("score", 0):.3f}, measured {where})</span><br>{body}</div>')
    return "".join(out)


def _text_coverage(tc: Optional[Dict[str, Any]]) -> str:
    """Which documents the search could read in full, and which it weighed by their abstract alone.

    A coverage gap is a limit on what the search could see, so it belongs in the scope table beside the
    corpus, not in a footnote. The field is part of the signed result.
    """
    if not tc:
        return ""
    r = tc.get("rescoring") or {}
    n = int(r.get("documents_rescored") or 0)
    unread = len(r.get("unread") or [])
    total = n + unread
    src = ", ".join(_esc(x) for x in (r.get("sources") or [])) or "none configured"
    if not total:
        return ('<tr><th>Full text read</th><td>no document was read in full; every document above was '
                'weighed by its title and abstract</td></tr>')
    return (f'<tr><th>Full text read</th><td>{n:,} of the {total:,} documents examined most closely were read '
            f'in full (sources: {src}); the remaining {unread:,} were weighed by title and abstract alone. '
            f'Passages quoted above say which text they were measured in.</td></tr>')


def _currency(cur: Optional[Dict[str, Any]]) -> str:
    """The newest document the search could have reached. Stated, never assumed.

    A corpus whose newest publication is months old has not searched those months. Saying so is the
    difference between a report an attorney can rely on and one they have to second-guess."""
    if not cur:
        return ('<tr><th>Corpus currency</th><td>not recorded for this search. The date of the most '
                'recent document in the corpus is not established here.</td></tr>')
    rows = []
    p = cur.get("patents")
    if p:
        rows.append(f"Patent documents: {p.get('n', 0):,} publications, "
                    f"{_fmt_date(p.get('oldest'))} to <b>{_fmt_date(p.get('newest'))}</b>.")
    q = cur.get("papers")
    if q:
        rows.append(f"Scientific publications: {q.get('n', 0):,} works in the corpus, "
                    f"{q.get('encoded', 0):,} of them carrying a vector.")
    rows.append("<b>Documents published after the dates above were not searched.</b>")
    return f'<tr><th>Corpus currency</th><td>{"<br>".join(rows)}</td></tr>'


def _patent_index(pi: Optional[Dict[str, Any]]) -> str:
    """Which patent index this search ran against, in terms a reader can check.

    The coverage figures later in the report were measured on US documents. When the search also ran
    over non-US documents, the report says plainly that no retrieval figure has been measured for those,
    rather than letting a US figure stand in for the whole corpus."""
    if not pi:
        return ""
    corp = pi.get("corpora") or {}
    us, rest = corp.get("usall", 0), corp.get("rest", 0)
    parts = []
    if us:
        parts.append(f"{us:,} US publications")
    if rest:
        parts.append(f"{rest:,} publications from other offices")
    what = " and ".join(parts) or f"{pi.get('rows', 0):,} publications"
    how = ("every document compared exactly" if pi.get("kind") == "exact" else
           f"approximate search over compressed vectors, with the {pi.get('rerank', 0):,} closest candidates "
           f"re-scored exactly")
    row = f'<tr><th>Patent documents searched</th><td>{what}; {_esc(how)}.'
    if rest:
        cal = pi.get("epo_calibration")
        if cal:
            pct = lambda xs: f"{round(min(xs) * 100)}% to {round(max(xs) * 100)}%"
            row += (f' On {cal.get("runs", 0)} independent samples of {cal.get("queries_per_run", 0)} European '
                    f'applications, against the documents EPO examiners cited, this index placed '
                    f'{pct(cal["worldwide_recall_1000"])} of them within the first 1,000 results, against '
                    f'{pct(cal["us_only_recall_1000"])} for US documents alone; for cited documents that are '
                    f'not US publications, {pct(cal["nonus_gold_recall_1000"])}. '
                    f'<b>Retrieval of {_esc(cal.get("not_measured", "some documents"))} has not been measured.</b>')
        else:
            row += (' <b>Retrieval performance on documents from offices other than the US has not been '
                    'measured.</b>')
        row += ' The coverage figures later in this report were measured on US documents.'
    return row + "</td></tr>"


def render_report(statement: Dict[str, Any], result: Dict[str, Any], *, matter: str, firm: str,
                  manifest: Optional[Dict[str, Any]] = None, applicant: str = "") -> str:
    st, res = statement, result
    hits: List[Dict[str, Any]] = res.get("hits", [])
    legs = st.get("legs") or {}
    cal = st.get("calibration") or {}
    pap = st.get("calibration_papers") or {}
    can = st.get("canary") or []
    g = sum(c["gold_n"] for c in can) or 1
    cutoff = _fmt_date(st.get("cutoff_date")) if st.get("cutoff_date") else "none given"
    by_src: Dict[str, int] = {}
    for h in hits:
        by_src[h.get("source", "paper")] = by_src.get(h.get("source", "paper"), 0) + 1

    comps = ""
    if manifest:
        agg: Dict[str, int] = {}
        for s in manifest.get("shards", []):
            c = s["path"].split("/")[0]
            agg[c] = agg.get(c, 0) + 1
        comps = "".join(f"<tr><td>{_esc(k)}</td><td>{v} files</td></tr>" for k, v in sorted(agg.items()))

    # Patent documents first, then non-patent literature, as an EPO search report separates them
    # (Form 1503 lists "patent documents" and "non-patent literature" apart). Interleaving them put a
    # scientific paper with its text licence-withheld at D1 of a patent search, which reads as a weak
    # first result when it is only a differently-licensed one.
    pats = [h for h in hits if h.get("source") == "patent"]
    npl = [h for h in hits if h.get("source") != "patent"]
    parts, n = [], 0
    if pats:
        parts.append("<h3 class=\"secthead\">Patent documents</h3>")
        for h in pats:
            n += 1
            parts.append(_citation_line(h, n) + _passages(h))
    if npl:
        parts.append("<h3 class=\"secthead\">Non-patent literature</h3>")
        for h in npl:
            n += 1
            parts.append(_citation_line(h, n) + _passages(h))
    cites = "".join(parts)
    leg_rows = "".join(f"<tr><td>{_esc(k)}</td><td>{v:,}</td></tr>" for k, v in legs.items())

    cal_line = ""
    if cal:
        cal_line = (f"For technology area <b>{_esc(cal.get('area'))}</b>, on a published benchmark of examiner "
                    f"citations (n={cal.get('n')}), this pipeline version placed <b>{cal.get('recall_100', 0):.0%}</b> "
                    f"of examiner-cited patent documents within the first 100 results and "
                    f"<b>{cal.get('recall_1000', 0):.0%}</b> within the first 1000.")
    if pap:
        cal_line += (f" For scientific publications, measured on held-out queries with each query's own citations "
                     f"excluded (n={pap.get('n')}): <b>{pap.get('recall_100', 0):.1%}</b> within the first 100.")

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Prior-art search report — {_esc(matter)}</title><style>{_REPORT_CSS}</style></head>
<body class="rpt">
<h1>Prior-art search report</h1>
<table class="kv scope">
<tr><th>Matter</th><td>{_esc(matter)}</td></tr>
{f'<tr><th>Applicant</th><td>{_esc(applicant)}</td></tr>' if applicant else ''}
<tr><th>Prepared for</th><td>{_esc(firm)}</td></tr>
<tr><th>Date of search (UTC)</th><td>{_esc(st.get('started_utc'))}</td></tr>
<tr><th>Subject of the search</th><td>the disclosure supplied, sha256 <code>{_esc((st.get('query_sha256') or '')[:16])}</code></td></tr>
<tr><th>Date limit applied</th><td>{_esc(cutoff)}</td></tr>
<tr><th>Classification predicted</th><td>{_esc(' '.join(st.get('cpc_predicted') or [])) or '—'}</td></tr>
<tr><th>Documents listed</th><td>{len(hits)} ({', '.join(f'{v} {k}s' for k, v in sorted(by_src.items()))})</td></tr>
</table>

<h2>Documents surfaced</h2>
<p class="muted">One entry per patent family: where several publications of one family were surfaced,
the best-matching is listed and its relatives named beneath it. Listed in ranked order. <b>No relevance category is assigned.</b> Under EPO practice the
X/Y/A categories amount to opinions on patentability; that judgment belongs to the reader of this report.
Each entry states which independent search strategies surfaced the document and, where computed, the
passage in it nearest to each part of the disclosure.</p>
{cites or '<p>No documents were returned.</p>'}

<h2>Scope of the search</h2>
<table class="kv scope">
<tr><th>Corpus searched</th><td><code>{_esc(st.get('index_snapshot'))}</code>, fixed at the time of search; manifest hash <code>{_esc((st.get('index_manifest_sha256') or '')[:16])}</code></td></tr>
<tr><th>Components</th><td><table>{comps or '<tr><td>manifest not attached</td></tr>'}</table></td></tr>
<tr><th>Coverage of the literature index</th><td>{(st.get('paper_coverage') or {}).get('dense_rows', 0):,} of {(st.get('paper_coverage') or {}).get('corpus_rows', 0):,} works carry a vector</td></tr>
<tr><th>Pipeline version</th><td><code>{_esc(st.get('pipeline_version'))}</code></td></tr>
{_text_coverage(st.get('text_coverage') or (result or {}).get('text_coverage'))}
{_patent_index(st.get('patent_index') or (result or {}).get('patent_index'))}
{_currency(st.get('corpus_currency') or (result or {}).get('corpus_currency'))}
</table>

<h2>Search strategy</h2>
<p>Independent strategies were run in parallel and their results combined; each entry above names the
strategies that surfaced it. Candidates examined per strategy:</p>
<table><tr><th>strategy</th><th>candidates</th></tr>{leg_rows}<tr><td><b>distinct candidates ranked</b></td><td><b>{st.get('candidates_total', 0):,}</b></td></tr></table>
<p class="muted">Documents dated on or after the date limit were excluded where the index holds a date:
patent documents by publication date, curated literature records by year. Literature records drawn from
the corpus-wide index carry no date in this index and are marked undated above
({st.get('undated_hits', 0)} of {st.get('hits_n', 0)} entries).</p>

<p class="muted">Where a passage is marked withheld, the document is a scientific publication whose
abstract is not under a licence that permits reproduction here. The measured distance stands; the
quotation does not. Patent documents are official publications and are quoted in full.</p>

<h2>How to read the distances above</h2>
<p>Each passage above carries the cosine between it and that part of the disclosure, under the encoder
that ranked the document. The number is a measurement of textual agreement. It is not a relevance
score, and no threshold separates a relevant document from an irrelevant one.</p>
<p>For placing a number: on a published benchmark of 120 examiner-searched patents, documents the
examiner actually cited had a nearest-passage cosine with <b>median 0.58</b> (10th–90th percentile
0.38–0.76). Random documents of the <i>same</i> classification scored <b>median 0.35</b> (0.16–0.55),
and random documents from the corpus at large <b>median 0.14</b> (0.02–0.34). The examiner-cited and
same-classification populations overlap across most of their range.</p>

<h2>Measured coverage of this pipeline</h2>
<p>{cal_line or 'No calibration figure was available for the predicted technology area.'}</p>
<p>Alongside this search, {len(can)} public queries whose examiner-cited art is known were run in the same
process, against the same corpus: {sum(c['found_100'] for c in can)} of {g} of their known citations appeared
within the first 100 results, {sum(c['found_1000'] for c in can)} of {g} within the first 1000.</p>

<div class="limit">
<h2 style="margin-top:0;border:none">What this report is, and is not</h2>
<p>This search <b>{_esc(res.get('claim_boundary'))}</b>.</p>
<p>It lists documents retrieved from the corpus named above by the strategies named above, within the
date limit stated. It assigns no relevance category, expresses no view on novelty or inventive step, and
makes no statement about documents outside that corpus. The measured coverage figures above are the
pipeline's performance on a published benchmark, not a property of this search.</p>
</div>

<h2>Verification</h2>
<p>This search ran inside an attested confidential-computing enclave. The accompanying certificate records
the hardware attestation, the corpus manifest hash committed in hardware, the network state during the
search, and the signature over the result. Both documents can be re-verified from the sealed artefacts
with the client software.</p>
</body></html>"""
