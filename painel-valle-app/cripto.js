/* cripto.js — Painel Valle (app). Criptografia ponta a ponta no aparelho.
   senha mestra → PBKDF2-SHA256 (600.000 rodadas, sal público) → chave privada X25519
   arquivo .enc = base64( efemera_pub(32) || nonce(12) || AES-256-GCM(cifrado+tag) )
   chave AES = HKDF-SHA256( X25519(privada, efemera_pub), info "painel-valle-v1" )
   Nada aqui sai do aparelho. A rotina que publica só conhece a chave pública. */
(function (g) {
  'use strict';
  const P = (1n << 255n) - 19n;
  const A24 = 121665n;
  const mod = (a) => { a %= P; return a < 0n ? a + P : a; };
  function pow(b, e) { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; }
  const inv = (a) => pow(a, P - 2n);
  function clamp(k) { k = Uint8Array.from(k); k[0] &= 248; k[31] &= 127; k[31] |= 64; return k; }
  function toBig(b) { let r = 0n; for (let i = b.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(b[i]); return r; }
  function toBytes(n) { const b = new Uint8Array(32); for (let i = 0; i < 32; i++) { b[i] = Number(n & 255n); n >>= 8n; } return b; }
  // Montgomery ladder (RFC 7748). scalar e u: Uint8Array(32), little-endian.
  function x25519(scalar, u) {
    const k = toBig(clamp(scalar));
    const x1 = toBig(u) & ((1n << 255n) - 1n);
    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
    for (let t = 254; t >= 0; t--) {
      const kt = (k >> BigInt(t)) & 1n;
      swap ^= kt;
      if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
      swap = kt;
      const A = mod(x2 + z2), AA = A * A % P, B = mod(x2 - z2), BB = B * B % P, E = mod(AA - BB);
      const C = mod(x3 + z3), D = mod(x3 - z3), DA = D * A % P, CB = C * B % P;
      x3 = mod((DA + CB) * (DA + CB)); z3 = x1 * mod((DA - CB) * (DA - CB)) % P;
      x2 = AA * BB % P; z2 = E * mod(AA + A24 * E) % P;
    }
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    return toBytes(x2 * inv(z2) % P);
  }
  const BASE = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();

  const b64u = {
    enc: (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    dec: (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); s += '='.repeat((4 - s.length % 4) % 4); return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
  };
  const b64 = { dec: (s) => Uint8Array.from(atob(s.replace(/\s+/g, '')), c => c.charCodeAt(0)) };

  async function derivarPrivada(senha, sal) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(senha.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: sal, iterations: 600000 }, base, 256);
    return clamp(new Uint8Array(bits));
  }
  // Devolve { privada, publica, chavePub: "pv1.<sal>.<pub>" }
  async function chaveDaSenha(senha, sal) {
    const privada = await derivarPrivada(senha, sal);
    const publica = x25519(privada, BASE);
    return { privada, publica, chavePub: 'pv1.' + b64u.enc(sal) + '.' + b64u.enc(publica) };
  }
  function lerChavePub(txt) {
    const p = txt.trim().split('.');
    if (p.length !== 3 || p[0] !== 'pv1') throw new Error('chave.pub inválida');
    return { sal: b64u.dec(p[1]), publica: b64u.dec(p[2]) };
  }
  async function decifrar(privada, base64Arquivo) {
    const raw = b64.dec(base64Arquivo);
    if (raw.length < 32 + 12 + 16) throw new Error('arquivo curto demais');
    const efPub = raw.slice(0, 32), nonce = raw.slice(32, 44), corpo = raw.slice(44);
    const segredo = x25519(privada, efPub);
    const hk = await crypto.subtle.importKey('raw', segredo, 'HKDF', false, ['deriveKey']);
    const aes = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('painel-valle-v1') }, hk, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const claro = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aes, corpo);
    return new TextDecoder().decode(claro);
  }
  const iguais = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  g.PainelCripto = { x25519, BASE, b64u, chaveDaSenha, lerChavePub, decifrar, iguais, clamp };
})(typeof window !== 'undefined' ? window : globalThis);
