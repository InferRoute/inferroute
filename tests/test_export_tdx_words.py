"""An Intel TDX record's own guide and audit brief describe Intel TDX (4 Nov).

The search machine is an Intel TDX confidential VM since 1 Nov 2026. VERIFY.md, AUDIT.md and record.html were written
for the AMD SEV-SNP machine and went on telling every reader that each search "ran inside an AMD SEV-SNP
confidential machine", with a VCEK and Microsoft's utility VM. These pin that a TDX-only record no longer says so,
and that each replacement still finds its SEV-SNP passage (a reworded base must fail here, not ship the AMD text).
"""
import json
import re

import pytest

from inferroute_cli import probant_export as E

TDX_OFFER = {"v": 1, "runtime_data": "", "evidence": {"tee": "intel-tdx", "quote": "AAAA", "ccel": "AAAA"},
             "endorsements": {"intel": {}, "google_launch_endorsement": ""}}
SNP_OFFER = {"evidence": "AAAA", "endorsements": "AAAA", "uvm_endorsements": "AAAA", "runtime_data": ""}

# What a TDX record must never tell its reader about its own searches.
SNP_ONLY = (r"AMD SEV-SNP confidential machine", r"\bVCEK\b", r"\bAzure\b", r"Microsoft", r"HOST_DATA",
            r"policy_b64", r"utility VM", r"kdsintf\.amd\.com", r"snpguest", r"acipolicygen")


def test_the_hardware_is_read_from_each_searchs_own_evidence():
    assert E.search_hardware([TDX_OFFER]) == {"tdx"}
    assert E.search_hardware([SNP_OFFER]) == {"snp"}
    assert E.search_hardware([TDX_OFFER, SNP_OFFER]) == {"tdx", "snp"}
    assert E.search_hardware([None, "x"]) == set()
    blobs = [json.dumps({"offer": TDX_OFFER}), b"not json", json.dumps({"no": "offer"})]
    assert E.search_hardware(E._evidence_offers(blobs)) == {"tdx"}


@pytest.mark.parametrize("base,subs", [("VERIFY_MD", "TDX_VERIFY_SUBS"), ("AUDIT_MD", "TDX_AUDIT_SUBS")])
def test_every_replacement_still_finds_its_sev_snp_passage(base, subs):
    text = getattr(E, base)
    for old, _ in getattr(E, subs):
        assert text.count(old) == 1, old[:80]


@pytest.mark.parametrize("make", [E.verify_md, E.audit_md])
def test_a_tdx_record_is_never_described_as_sev_snp(make):
    text = make({"tdx"})
    found = [p for p in SNP_ONLY if re.search(p, text)]
    assert found == [], found
    assert "Intel" in text


def test_the_brief_keeps_its_claims_and_their_order_for_a_tdx_record():
    titles = re.findall(r"^\d\. \*\*([^*]+)\*\*", E.audit_md({"tdx"}), re.M)
    assert titles[:8] == re.findall(r"^\d\. \*\*([^*]+)\*\*", E.AUDIT_MD, re.M)[:8]
    assert E._brief(True, {"tdx"}) == E.audit_md({"tdx"})
    assert E._brief(True) == E.AUDIT_MD                                   # older callers: unchanged


def test_sev_snp_and_unknown_records_keep_their_text():
    assert E.verify_md({"snp"}) == E.VERIFY_MD and E.verify_md(set()) == E.VERIFY_MD
    assert E.audit_md({"snp"}) == E.AUDIT_MD


def test_a_mixed_record_says_it_is_mixed_and_carries_both_derivations():
    v = E.verify_md({"tdx", "snp"})
    assert "mixes two kinds of search machine" in v and "## For the searches that ran on Intel TDX" in v
    assert "VCEK" in v and "go-tdx-guest" in v
    assert "mixes two kinds of search machine" in E.audit_md({"tdx", "snp"})
