#!/usr/bin/env python3
"""
cifrar.py — cifra os dados do painel para o app (Painel Valle, PWA).

Uso:
  python3 espelho/cifrar.py <pasta_com_json_em_claro> <pasta_dados_do_repositorio>

Lê `dados/chave.pub` (formato pv1.<sal>.<chave_publica>) no repositório, e para cada
`*.json` da pasta em claro grava `<nome>.enc` na pasta dados/ e atualiza `indice.json`.

Esquema (ponta a ponta, a rotina NUNCA conhece a senha):
  - o telefone deriva a chave privada X25519 da senha mestra (PBKDF2-SHA256, 600.000 rodadas,
    sal público) e publica só a chave pública;
  - a rotina gera um par efêmero X25519, faz o acordo com a chave pública do telefone,
    passa o segredo por HKDF-SHA256 (info "painel-valle-v1") e cifra com AES-256-GCM;
  - arquivo .enc = base64( efemera_pub(32) || nonce(12) || cifrado+tag ).
Quem achar o repositório vê só texto sem sentido. Só a senha mestra decifra.
Dependência: pip install cryptography
"""
import base64
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"painel-valle-v1"


def b64u_decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def ler_chave_publica(caminho: str) -> X25519PublicKey:
    with open(caminho, encoding="utf-8") as f:
        txt = f.read().strip()
    partes = txt.split(".")
    if len(partes) != 3 or partes[0] != "pv1":
        raise SystemExit("chave.pub inválida — esperado pv1.<sal>.<chave_publica>")
    pub = b64u_decode(partes[2])
    if len(pub) != 32:
        raise SystemExit("chave pública com tamanho errado")
    return X25519PublicKey.from_public_bytes(pub)


def cifrar(pub: X25519PublicKey, claro: bytes) -> str:
    efemera = X25519PrivateKey.generate()
    segredo = efemera.exchange(pub)
    chave = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(segredo)
    nonce = os.urandom(12)
    cifrado = AESGCM(chave).encrypt(nonce, claro, None)
    from cryptography.hazmat.primitives import serialization
    ef_pub = efemera.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(ef_pub + nonce + cifrado).decode("ascii")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    claro_dir, dados_dir = sys.argv[1], sys.argv[2]
    pub = ler_chave_publica(os.path.join(dados_dir, "chave.pub"))
    agora = datetime.now(timezone.utc).isoformat(timespec="seconds")
    arquivos = []
    for nome in sorted(os.listdir(claro_dir)):
        if not nome.endswith(".json"):
            continue
        with open(os.path.join(claro_dir, nome), "rb") as f:
            claro = f.read()
        json.loads(claro)  # falha cedo se o JSON estiver quebrado
        base = nome[:-5]
        with open(os.path.join(dados_dir, base + ".enc"), "w", encoding="ascii") as f:
            f.write(cifrar(pub, claro))
        arquivos.append({"id": base, "arquivo": base + ".enc", "bytes": len(claro)})
        print(f"cifrado: {nome} -> {base}.enc ({len(claro)} bytes em claro)")
    indice = {"versao": 1, "atualizadoEm": agora, "arquivos": arquivos}
    with open(os.path.join(dados_dir, "indice.json"), "w", encoding="utf-8") as f:
        json.dump(indice, f, ensure_ascii=False, indent=1)
    print(f"indice.json: {len(arquivos)} arquivo(s), {agora}")


if __name__ == "__main__":
    main()
