"""Exercise audit export from an extracted wheel, with no source checkout on sys.path."""
import hashlib,json,subprocess,sys,tempfile,zipfile
from pathlib import Path
wheel=Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='probant-wheel-') as td:
 root=Path(td); installed=root/'installed'
 with zipfile.ZipFile(wheel) as z: z.extractall(installed)
 code=r'''
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from inferroute_cli import probant_export as E, probant_check
root=Path(sys.argv[2]); installed=Path(sys.argv[1])
assert Path(E.__file__).is_relative_to(installed), E.__file__
assets=installed/'inferroute_cli'/'trust'
for name in ('publication-key-attestation.json','publication-key-attestation.bundle'):
 assert (assets/name).is_file(), 'wheel missing '+name
att=json.loads((assets/'publication-key-attestation.json').read_text())
ref=root/'reference.json'; ref.write_text('{}')
probant_check.published_reference=lambda:(ref,att['publication_key'])
rec=root/'record';rec.mkdir()
(rec/'searches.json').write_text('[]')
(rec/'MANIFEST.json').write_text('{}')
(rec/'session-fixture.receipt.json').write_text('{}')
(rec/'VERIFY.md').write_text('STALE INSTRUCTIONS')
pack=E.write_audit_pack(rec,root/'pack')
m=json.loads((pack/'MANIFEST.json').read_text())
for name in ('publication-key-attestation.json','publication-key-attestation.bundle'):
 path='trust-anchors/'+name
 assert (pack/path).read_bytes()==(assets/name).read_bytes()
 assert m['trust_anchors']['files'][path]==hashlib.sha256((pack/path).read_bytes()).hexdigest()
assert (pack/'VERIFY.md').read_text()==E.VERIFY_MD
assert (pack/'verify_record.py').read_bytes()==E._installed_verifier()
print('PASS wheel-only export:',m['client_version'],sorted(m['trust_anchors']['files']))
'''
 subprocess.run([sys.executable,'-I','-c',code,str(installed),str(root)],cwd=root,check=True)
