#!/usr/bin/env python3
"""Fabrique votre clé Probant, et affiche la partie publique.

Ce fichier ne fait que cela. Il n'installe rien, ne contacte aucun serveur, et n'ouvre aucun réseau :
vous pouvez le lire en entier avant de l'exécuter — c'est la raison de sa taille.

Il crée deux clés dans votre dossier personnel, sous ~/.inferroute/confidential/identity/ :
  - une clé ML-KEM-768, qui sert à vous adresser un envoi chiffré ;
  - une clé Ed25519, qui sert à signer ce que vous envoyez.
Les parties SECRÈTES restent sur votre disque et ne sont jamais affichées. Seule la partie publique
est imprimée, et c'est elle que vous renvoyez par courriel.

    python3 cle-probant.py

Besoin : Python 3 et la bibliothèque `cryptography` (version 50 ou plus). Si elle manque, le script
vous le dit et s'arrête sans rien écrire.
"""
import base64
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

SCHEMA_IDENTITY = "inferroute.probant-identity/1"
SCHEMA_CARD = "inferroute.probant-contact/1"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def fingerprint(mlkem_pub: bytes, ed_pub: bytes) -> str:
    """Une empreinte courte de la clé : de quoi la désigner sans recopier le bloc entier."""
    digest = hashlib.sha256(b"probant-identity-v1" + mlkem_pub + ed_pub).hexdigest()
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4))


def main() -> int:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import mlkem
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        sys.stderr.write(
            "\n  Il manque la bibliothèque `cryptography` (version 50 ou plus).\n"
            "      python3 -m pip install 'cryptography>=50'\n"
            "  Rien n'a été écrit.\n\n")
        return 1

    home = Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute"))
    d = home / "confidential" / "identity"
    path = d / "identity.json"

    if path.is_file():
        # Ne JAMAIS écraser une clé existante : ce qui lui a été adressé deviendrait illisible.
        held = json.loads(path.read_text())
        print(f"\n  Vous avez déjà une clé Probant — empreinte {held['fingerprint']}")
        print(f"  ({path})\n  Rien n'a été modifié. Voici votre partie publique :\n")
    else:
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        # ML-KEM-768 : on conserve la GRAINE et non la clé secrète dérivée, parce que c'est la graine
        # que cette bibliothèque sait recharger (from_seed_bytes).
        raw_seed = os.urandom(64)
        mlkem_pub = mlkem.MLKEM768PrivateKey.from_seed_bytes(raw_seed).public_key().public_bytes_raw()
        ed = Ed25519PrivateKey.generate()
        ed_pub = ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_sk = ed.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        held = {"schema": SCHEMA_IDENTITY,
                "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mlkem_pub": b64(bytes(mlkem_pub)), "mlkem_sk": b64(b""), "mlkem_seed": b64(raw_seed),
                "ed_pub": b64(ed_pub), "ed_sk": b64(ed_sk),
                "fingerprint": fingerprint(bytes(mlkem_pub), ed_pub)}
        path.write_text(json.dumps(held, indent=1))
        os.chmod(path, 0o600)
        print(f"\n  Votre clé Probant a été créée — empreinte {held['fingerprint']}")
        print(f"  (partie secrète : {path}, lisible par vous seul)\n")

    card = {"schema": SCHEMA_CARD, "mlkem_pub": held["mlkem_pub"], "ed_pub": held["ed_pub"],
            "fingerprint": held["fingerprint"]}
    print("  ── votre clé publique — copiez tout ce qui suit et renvoyez-le ──\n")
    print(json.dumps(card, indent=1))
    print("\n  ── fin ──\n")
    print("  Ce bloc ne contient que des clés publiques : qui le lit n'apprend rien et n'ouvre rien.")
    print("  Renvoyez-le par courriel, tel quel.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
