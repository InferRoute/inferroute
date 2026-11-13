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
    # /3 (v19, 12 Nov 2026): every sentence re-checked against the GCE Intel TDX image as built. /2 carried Azure
    # (ACI) claims that are false here: an attestation sidecar, the platform's own containers in the protected
    # machine, a container policy and HOST_DATA, SEV-SNP, and sources "not published".
    "schema": "inferroute.search-plaintext-handling/3",
    "grades": {g: d for g, d in zip(GRADES, (
        "impossible by a mechanism the measurement commits to; verifiable by the reader",
        "a check ran and passed at a stated time; evidence, not impossibility",
        "our word, labelled as such"))},

    "network_egress": {
        "grade": "ENFORCED",
        "claim": "While serving, the search process cannot open a network connection: socket() and connect() "
                 "fail with EPERM under a seccomp filter that the measured image's search program installs on "
                 "every thread before it accepts the first request, for the life of the process and of any "
                 "child. Independently, the image's firewall (nftables, loaded before the network interface "
                 "comes up, its output policy drop) lets the search account send off the machine only replies on "
                 "the search port, and drops everything the ranking engine's account sends off the machine.",
        "scope": "Covers the SERVING period. The network touches that precede it are a separate, weaker row "
                 "below. The network service's DHCP client and the kernel's ARP are outside the firewall's reach "
                 "(DHCP uses a raw packet socket, which nftables does not see; ARP is not in its inet table): that "
                 "they carry no query rests on what those two do, not on the firewall. Neither runs in, or "
                 "receives anything from, the search or engine processes.",
    },
    "pre_service_network": {
        "grade": "OBSERVED",
        "claim": "Before the search starts, only a separate fetch account may reach the network: it reads the "
                 "index location from the cloud's instance metadata server, downloads the index from Google "
                 "Cloud Storage, and downloads Intel's and Google's attestation documents (TCB information, "
                 "revocation lists, the launch endorsement); the machine's own resolver looks up those names. "
                 "That allowance is then emptied, the emptying is checked, and only then does the search start. "
                 "The search process itself makes no outbound request: it reaches the quote helper and the "
                 "ranking engine over local unix sockets it opens before its seal. No query has arrived at this "
                 "point, so none of these carries query or result text.",
        "scope": "Enumerated by reading the published image sources (the fetch step, the firewall rules and the "
                 "boot checks), and bounded by the firewall in the measured image; the seccomp filter is "
                 "installed after them and says nothing about them.",
    },
    "application_persistence": {
        "grade": "OBSERVED",
        "claim": "A sentinel query put through a real search over real HTTP reached no file and neither output "
                 "stream; the only plaintext copy is the record bundle the client asked for, on the client's own "
                 "machine. On the image, the root filesystem is read-only and verity-checked, every writable "
                 "path is in memory, and there is no swap.",
        "evidence": "tests/test_plaintext_never_leaves_the_process.py; the image's partition and boot settings",
        "scope": "Disk and output streams — NOT the network, which the enforced row above covers. The two are "
                 "adjacent and neither substitutes for the other.",
    },
    "application_access_logs": {
        "grade": "ENFORCED",
        "claim": "HTTP access logging is disabled in the handler, and the measured image's units for the search, "
                 "the ranking engine, the fetch step and the quote helper send standard output and standard "
                 "error to /dev/null and deny core dumps (the unit policy in the image the boot measurement "
                 "covers).",
    },
    "request": {
        "grade": "ASSERTED",
        "claim": "The request is opened in the search service process after receipt of a sealed envelope; the "
                 "query text then goes to the ranking engine over a local socket, in a process of its own per "
                 "request.",
    },
    "response": {
        "grade": "ENFORCED",
        "claim": "The result is sealed to the per-request reply key and its key hash is signed.",
    },

    "limits": {
        "memory_zeroization": {
            "grade": "ASSERTED",
            "claim": "Not guaranteed, and we do not claim it. Python cannot reliably zero a string — they are "
                     "immutable and copied — so 'wiped' would be a promise we could not honour. What IS true and "
                     "checkable: there is no swap, core dumps are denied, every writable path is in memory, memory "
                     "is encrypted against the host by Intel TDX, and the machine is destroyed after use.",
        },
        "platform": {
            "grade": "ASSERTED",
            "claim": "The virtual firmware, the TDX module and the instance metadata server belong to Google and "
                     "Intel. We pin the firmware measurement per machine shape and check Intel's and Google's "
                     "signatures, but we do not control that code. The image runs no cloud guest agent.",
        },
        "timing_and_size": {
            "grade": "ASSERTED",
            "claim": "Each reply is padded to one fixed size and leaves at one of two fixed intervals after the "
                     "request is taken up: one for a search, a longer one for a survey. So a single reply's size and "
                     "time say which of the two kinds it was, and nothing beyond that; the record states the kind. "
                     "A request refused before it is taken up is answered at once. When requests arrive, how many "
                     "arrive, and how long each waited in line stay observable from outside the machine.",
        },
        "source_provenance": {
            "grade": "OBSERVED",
            "claim": "The image sources and the build script are published with each image (inferroute.ai/build), "
                     "and two independent no-cache builds of the same sources produced byte-identical images, so a "
                     "reader can rebuild the image and compare its measurement. The index and the ranking models "
                     "are data the image loads, bound by their hashes in the attestation, not sources.",
        },
    },
}

PRIVACY_CONTRACT_V2 = {
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


# Every contract a client accepts, keyed by the sha256 of its canonical JSON. A client accepts any known one, so a
# change of wording needs no flag day: machines on the previous image (v18 and earlier carry /2) and on the next
# (v19 carries /3) both verify during a rollover. A contract leaves this set only with a client release.
KNOWN_PRIVACY_CONTRACTS = {hashlib.sha256(search.canonical(c)).hexdigest(): c
                           for c in (PRIVACY_CONTRACT, PRIVACY_CONTRACT_V2)}


def known_contract(obj: Any) -> bool:
    """True when `obj` is exactly one of the known contracts (by canonical hash)."""
    try:
        return hashlib.sha256(search.canonical(obj)).hexdigest() in KNOWN_PRIVACY_CONTRACTS
    except Exception:                                       # noqa: BLE001
        return False


def salted(request_id: str, obj: Any) -> str:
    return hashlib.sha256(request_id.encode() + search.canonical(obj)).hexdigest()
