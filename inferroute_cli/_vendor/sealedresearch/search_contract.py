"""The sealed-search CONTRACT surface: names shared between the enclave service and every
verifying client. Everything here already reaches clients (the privacy contract rides in each
/offer reply; KIND and the hex shapes appear in every statement; salted() is the documented
statement-hash construction) — extracted 2026-10-01 so the client-side verifier can import the
contract WITHOUT importing the service (search_service stays out of the open-source WHITELIST
pending its own publication ruling). Both sides import from here; drift is structurally gone.
"""
import hashlib
import re
from typing import Any

from . import search

HEX32 = re.compile(r"^[0-9a-f]{64}$")
HEX16 = re.compile(r"^[0-9a-f]{32}$")
KIND = "sealed-search"
# Code-level handling disclosure included in runtime_data, then covered by the hardware report's
# REPORT_DATA commitment and by every per-request signed statement's runtime_data_sha256. These are
# assertions about this service implementation, not claims about resolved CCE fragments, the utility VM,
# network egress, swap, crash dumps, or memory zeroization.
# EVERY CLAIM CARRIES AN EVIDENTIARY GRADE, from a closed set of three. A reader who can sort each
# row into one of these without asking us is the whole pitch in miniature — and the grades are
# checked by tests/test_privacy_contract_grades.py, so a new claim cannot arrive ungraded.
#
#   ENFORCED  impossible by a mechanism, where the mechanism is committed to by the measurement and
#             the reader can verify it. Nobody had to look, and nothing depends on anyone's judgment.
#   OBSERVED  a check ran and passed, at a stated time, by a named instrument. Evidence, not proof:
#             it says what was seen, not what is impossible.
#   ASSERTED  our word. Labelled as such so it is never mistaken for either of the above.
GRADES = ("ENFORCED", "OBSERVED", "ASSERTED")

PRIVACY_CONTRACT = {
    "schema": "inferroute.search-plaintext-handling/2",
    "grades": {g: d for g, d in zip(GRADES, (
        "impossible by a mechanism the measurement commits to; verifiable by the reader",
        "a check ran and passed at a stated time; evidence, not impossibility",
        "our word, labelled as such"))},

    "network_egress": {
        "grade": "ENFORCED",
        "claim": "After the service starts, outbound network connections are IMPOSSIBLE: socket() "
                 "and connect() fail with EPERM under a kernel filter that the measured image "
                 "installs unconditionally before accepting the first request, for the life of the "
                 "process and of any child. Nobody checked this and nothing needs to have looked.",
        "scope": "Covers the SERVING period only. The two network touches that precede it — fetching "
                 "the index, and one attestation from the sidecar on localhost — are outside what "
                 "the filter can say anything about, and are graded separately below.",
    },
    "pre_service_network": {
        "grade": "OBSERVED",
        "claim": "Before the seal, the enclave makes exactly two outbound requests: it downloads the "
                 "index, and it asks the local attestation sidecar for a hardware report over its "
                 "runtime data. Neither carries query or result text.",
        "scope": "Enumerated by reading the code, not enforced. The filter is installed after both "
                 "and says nothing about either.",
    },
    "application_persistence": {
        "grade": "OBSERVED",
        "claim": "A sentinel query put through a real search over real HTTP reached no file and "
                 "neither output stream; the only plaintext copy is the record bundle the client "
                 "asked for, on the client's own machine.",
        "evidence": "tests/test_plaintext_never_leaves_the_process.py",
        "scope": "Disk and output streams — NOT the network, which the enforced row above covers. "
                 "The two are adjacent and neither substitutes for the other.",
    },
    "application_access_logs": {
        "grade": "ENFORCED",
        "claim": "HTTP access logging is disabled in the handler, and the container policy denies "
                 "runtime logging, stack dumps and unencrypted scratch — all three are in the "
                 "policy the signed HOST_DATA is the hash of.",
    },
    "request": {
        "grade": "ASSERTED",
        "claim": "The request is opened in the search service process after receipt of a sealed "
                 "envelope.",
    },
    "response": {
        "grade": "ENFORCED",
        "claim": "The result is sealed to the per-request reply key and its key hash is signed.",
    },

    "limits": {
        "memory_zeroization": {
            "grade": "ASSERTED",
            "claim": "Not guaranteed, and we do not claim it. Python cannot reliably zero a string — "
                     "they are immutable and copied — so 'wiped' would be a promise we could not "
                     "honour. What IS true and checkable: there is no swap, crash dumps are denied "
                     "by the measured policy, scratch is encrypted, memory is encrypted against the "
                     "host by SEV-SNP, and the enclave is destroyed after use.",
        },
        "platform_containers": {
            "grade": "ASSERTED",
            "claim": "The cloud platform runs its own containers inside the same protected machine. "
                     "We identify and pin them but do not control them, and the filter above "
                     "constrains OUR process, not theirs.",
        },
        "timing_and_size": {
            "grade": "ASSERTED",
            "claim": "How long a search took and how large it was are observable from outside the "
                     "machine and no mechanism here changes that.",
        },
        "source_provenance": {
            "grade": "OBSERVED",
            "claim": "The image build is reproducible: two independent no-cache builds produced "
                     "byte-identical layers. That is our measurement; a reader cannot yet repeat it, "
                     "because the application sources and the deployment template are not published.",
        },
    },
}


def salted(request_id: str, obj: Any) -> str:
    return hashlib.sha256(request_id.encode() + search.canonical(obj)).hexdigest()
