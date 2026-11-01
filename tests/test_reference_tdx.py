"""`ir probant reference add-tdx`: the TDX fields the shipped verifier reads (tdx_image_sha384 + loads, tdx_rtmr0)."""
import hashlib
import struct

import pytest

from inferroute_cli import reference as R


def _pe(sections):
    """A minimal PE32+ with the given (name, bytes) sections, enough for Authenticode and section lookup."""
    nsec, opt_size, pe_off = len(sections), 240, 0x80
    hdr_size = 0x400
    out = bytearray(hdr_size)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, pe_off)
    out[pe_off:pe_off + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", out, pe_off + 4, 0x8664, nsec, 0, 0, 0, opt_size, 0x22)
    opt = pe_off + 24
    struct.pack_into("<H", out, opt, 0x20B)
    struct.pack_into("<I", out, opt + 60, hdr_size)
    st, ptr = opt + opt_size, hdr_size
    body = bytearray()
    for i, (name, data) in enumerate(sections):
        raw = data + bytes(-len(data) % 0x200)
        struct.pack_into("<8sIIII", out, st + 40 * i, name.encode(), len(data), ptr, len(raw), ptr)
        body += raw
        ptr += len(raw)
    return bytes(out + body)


KERNEL = _pe([(".text", b"kernel" * 100)])
UKI = _pe([(".text", b"stub" * 50), (".cmdline", b"roothash=" + b"a" * 64), (".linux", KERNEL)])
H = "ab" * 48


def test_add_tdx_names_the_image_and_the_kernel_it_loads():
    ref = R.add_tdx({"policy_sha256": ["11" * 32]}, UKI, {"c3-standard-22": H}, valid_from="2026-10-31T00:00:00Z")
    img = ref["tdx_image_sha384"][0]
    assert img["value"] == R.pe_authenticode_sha384(UKI) and len(img["value"]) == 96
    assert img["loads"] == [R.pe_authenticode_sha384(KERNEL)]
    assert ref["tdx_rtmr0"] == [{"value": H, "shape": "c3-standard-22", "valid_from": "2026-10-31T00:00:00Z"}]
    assert ref["policy_sha256"] == ["11" * 32]          # the AMD fields are kept


def test_authenticode_skips_the_checksum():
    other = bytearray(UKI)
    struct.pack_into("<I", other, 0x80 + 24 + 64, 0xDEADBEEF)  # CheckSum field
    assert R.pe_authenticode_sha384(bytes(other)) == R.pe_authenticode_sha384(UKI)
    other[-1] ^= 1
    assert R.pe_authenticode_sha384(bytes(other)) != R.pe_authenticode_sha384(UKI)


def test_adding_drops_a_stale_signature():
    ref = R.add_tdx({"sig": "00", "publication_key": "11"}, UKI, {"c3-standard-8": H})
    assert "sig" not in ref and "publication_key" not in ref


@pytest.mark.parametrize("pins", [{}, {"c3-standard-8": "00" * 48}, {"c3-standard-8": "zz"}, {"Bad Shape": H}])
def test_refuses_pins_that_name_nothing(pins):
    with pytest.raises(R.ReferenceError):
        R.add_tdx({}, UKI, pins)


def test_refuses_an_image_without_a_kernel():
    with pytest.raises(R.ReferenceError):
        R.add_tdx({}, KERNEL, {"c3-standard-8": H})


def test_supersede_closes_the_previous_image():
    ref = R.add_tdx({}, UKI, {"c3-standard-8": H}, valid_from="2026-10-31T00:00:00Z")
    uki2 = _pe([(".text", b"stub2" * 50), (".linux", KERNEL)])
    ref = R.add_tdx(ref, uki2, {"c3-standard-8": H}, valid_from="2026-11-05T00:00:00Z", supersede=True)
    first, second = ref["tdx_image_sha384"]
    assert first["valid_to"] == "2026-11-05T00:00:00Z" and "valid_to" not in second


def test_the_shipped_verifier_accepts_what_add_tdx_wrote(tmp_path):
    import importlib.util
    from pathlib import Path
    script = Path(R.__file__).parent / "pi_attested" / "verify_record.py"
    spec = importlib.util.spec_from_file_location("verify_record_tdx", script)
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    ref = R.add_tdx({}, UKI, {"c3-standard-22": H})
    info = {"image_sha384": R.pe_authenticode_sha384(UKI), "boot_apps": [R.pe_authenticode_sha384(UKI),
            R.pe_authenticode_sha384(KERNEL)], "rtmr0": H}
    ref.update(index_manifest_sha256=["22" * 32], model_manifest_sha256=["33" * 32])
    c = V.Checks()
    V.check_tdx_identity(c, {"index_manifest_sha256": "22" * 32, "model_manifest_sha256": "33" * 32}, info, ref,
                         "2026-11-01T00:00:00Z", live=True)
    assert c.failed == []
