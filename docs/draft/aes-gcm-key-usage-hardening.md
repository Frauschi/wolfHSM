# AES-GCM IV / key-usage hardening — findings and design

Status: **draft / design review**. This document records a source-verified review
of wolfHSM's key-usage enforcement and AES-GCM IV handling against a
fully-malicious-client threat model, and proposes a design to close the gaps it
finds. The cryptographic background is summarized only where it is load-bearing
for a decision; the focus here is what the wolfHSM source actually does today and
what would have to change.

All file:line citations are against the tree as reviewed.

---

## 1. Threat model under review

wolfHSM is a client–server design: the server (HSM core) holds key material; the
client runs in an untrusted environment and references keys by `keyId` without
ever seeing key bytes (`docs/src/4-Architecture.md`). The question this review
answers is narrow and concrete:

> For a key the HSM **withholds** (`WH_NVM_FLAGS_NONEXPORTABLE`) but lets a client
> **use** (`WH_NVM_FLAGS_USAGE_ENCRYPT`), can a malicious client extract enough
> *authority* over that key — through legitimate API calls — to defeat the
> guarantee the key flags imply?

The cryptographic facts that make this more than theoretical (all standard, none
wolfHSM-specific):

- AES-GCM authentication depends on the GHASH subkey `H = E_K(0^128)` and, per
  nonce, on `E_K(J0)`. Neither is the key `K`, but both are *authority*: with `H`
  and one valid `(A,C,T)` under a nonce `N`, an attacker forges valid tags for
  arbitrary `(A',C')` under `N` offline.
- A **raw single-block AES (ECB) oracle over the same key** yields `H` and
  `E_K(J0)` for any nonce directly — no IV reuse needed. This is a total break of
  that key's GCM authentication.
- IV/nonce **reuse** under AES-GCM (the "forbidden attack", Joux) also recovers
  `H`; and on the confidentiality side, a pinned `(K, IV)` gives keystream reuse
  (two-time pad / chosen-plaintext keystream extraction).

The unifying principle the design is built around:

> **For any key the HSM withholds, the client must not be able to drive that key
> toward a raw cipher primitive, or toward an attacker-controlled-nonce AEAD
> encryption** — both collapse the gap between "uses the key" and "holds the key."

---

## 2. What the code does today (verified)

### 2.1 Usage flags are direction-bound, not mode-bound

The key-usage policy bits live in `whNvmMetadata.flags` (`whNvmFlags`,
`uint16_t`), defined in `wolfhsm/wh_common.h:84-113`:

```
USAGE_ENCRYPT (1<<5)  USAGE_DECRYPT (1<<6)
USAGE_SIGN    (1<<7)  USAGE_VERIFY  (1<<8)
USAGE_WRAP    (1<<9)  USAGE_DERIVE  (1<<10)
```

These distinguish **direction** (encrypt vs decrypt, sign vs verify) and the
**wrap/derive** roles, but there is **no algorithm or cipher-mode dimension**. A
key carrying `USAGE_ENCRYPT` is permitted to encrypt under *any* AES mode the
server exposes.

`whNvmMetadata` itself (`wolfhsm/wh_common.h:122-128`) carries no algorithm/mode
field. The file even notes "NVM metadata does not carry an algorithm type"
(`wolfhsm/wh_common.h:148-150`). The struct is a fixed 32 bytes
(`id`2 + `access`2 + `flags`2 + `len`2 + `label`24), `memcpy`-serialized into NVM
and into wrapped-key blobs (e.g. `src/wh_server_keystore.c:1470-1471`). Flag bits
**12–15 are free**; bits 0–11 are assigned.

### 2.2 The enforcement primitive

`wh_Server_KeystoreEnforceKeyUsage()` (`src/wh_server_keystore.c:2883-2904`) is a
pure bit-mask check:

```c
requiredUsage &= WH_NVM_FLAGS_USAGE_ANY;
actualFlags    = meta->flags & WH_NVM_FLAGS_USAGE_ANY;
if ((actualFlags & requiredUsage) == requiredUsage) return WH_ERROR_OK;
return WH_ERROR_USAGE;
```

`wh_Server_KeystoreFindEnforceKeyUsage()` (`:2906-2926`) wraps it with a key
lookup. There is **no single chokepoint**: every AES handler calls
`FreshenKey` + `EnforceKeyUsage` inline, each choosing the flag it thinks
applies.

### 2.3 Every AES mode checks only direction — and ECB is exposed

Dispatch is a `switch (action) → switch (algoType)` in
`src/wh_server_crypto.c:5089-5126`. Each handler, for a non-erased keyId, calls
`EnforceKeyUsage` with `enc ? USAGE_ENCRYPT : USAGE_DECRYPT`:

| Mode | Handler | Usage flag checked | IV source |
|------|---------|--------------------|-----------|
| AES-CTR | `_HandleAesCtr` (`:2455`) | ENCRYPT/DECRYPT (`:2509`) | client (`:2492`) |
| AES-ECB | `_HandleAesEcb` (`:2766`) | ENCRYPT/DECRYPT (`:2817`) | n/a |
| AES-CBC | `_HandleAesCbc` (`:3046`) | ENCRYPT/DECRYPT (`:3101`) | client (`:3086`) |
| AES-GCM | `_HandleAesGcm` (`:3338`) | ENCRYPT/DECRYPT (`:3410`) | **client** (`:3378`) |
| AES-CMAC | `_HandleCmac` (`:3733`) | SIGN/VERIFY (`:3704`) | n/a |
| key/data wrap | `_AesGcmKeyWrap`/`Unwrap` (`keystore:1149/1234`) | WRAP | **server RNG** on wrap (`:1204`), blob on unwrap |

No path *bypasses* the check — the docs' "no client request can bypass it" claim
is literally true for the check that exists. The problem is the check's
**granularity**, not its coverage:

- **AES-ECB is compiled in under `HAVE_AES_ECB`** (`:5100-5106`) and gated only on
  `USAGE_ENCRYPT`/`USAGE_DECRYPT` — the *same* flag a GCM key needs. So a key
  provisioned `NONEXPORTABLE | USAGE_ENCRYPT` for GCM is usable as a **raw
  `E_K` ECB oracle**. The attacker computes `H = E_K(0^128)` and any `E_K(J0)`
  directly → forges GCM tags under any nonce → total break of that key's GCM
  authentication. No IV reuse required.
- Even without ECB, the same `USAGE_ENCRYPT` key can be driven through CBC/CTR
  with a chosen IV, and through **GCM with a client-pinned IV**, enabling the
  forbidden attack and keystream extraction.

Inline (client-supplied) keys skip enforcement entirely — that is by design and
out of scope (the client already holds those bytes).

### 2.4 AES-GCM IV is client-controlled with no uniqueness management

In `_HandleAesGcm`, the IV is taken straight from the request packet
(`src/wh_server_crypto.c:3378`, `iv = key + key_len`; length from `req.ivSz`,
`:3363`) and passed to `wc_AesGcmEncrypt` unmodified. There is **no
server-generated-IV path** for general AES-GCM, **no uniqueness/counter state**,
and **no per-key message cap**. The client fully controls (and can pin/repeat)
the nonce.

The server *does* have a DRBG: `whServerCryptoContext.rng`
(`wolfhsm/wh_server.h:73-74`), already used to generate wrap IVs
(`src/wh_server_keystore.c:1204,1353`) and to service client RNG requests
(`src/wh_server_crypto.c:1354`). So a server-managed-nonce path is feasible with
existing infrastructure.

### 2.5 Wrapped keys carry the policy (good)

Wrapped-key metadata is the same `whNvmMetadata`, encrypted inside the blob and
re-checked on unwrap (`src/wh_server_keystore.c:1234-1276`). Whatever policy model
we adopt is automatically bound into wrapped blobs — no separate work, as long as
the new policy field lives in `whNvmMetadata`.

---

## 3. The two questions, decided independently

Following the framing from the design discussion:

- **Question A — should wolfHSM support the fully-malicious-client model for
  withheld symmetric keys?** A legitimate product-scope call. "No" is defensible.
- **Question B — does wolfHSM currently *claim* a guarantee it does not deliver?**

On B, the documentation (`docs/src/5-Features.md:361-389`) presents usage flags as
a server-enforced security control and states "no client request can bypass it"
(`:378`), with examples like a `USAGE_WRAP | NONEXPORTABLE` KEK that "cannot
itself be exported or used for general encryption" (`:388`). That specific
example holds (encryption needs `USAGE_ENCRYPT`). What the docs **do not** say,
and what is **not true**, is that a `NONEXPORTABLE | USAGE_ENCRYPT` AES key is
safe to expose to a malicious client: §2.3 shows it is fully forgeable via ECB
(or via GCM nonce-pinning). The flag name `NONEXPORTABLE` also oversells — it
protects key *bytes*, while every attack here extracts *authority* through
legitimate use.

So the implied guarantee is leaky. Per the discussion, the only unacceptable
state is shipping that leaky implied guarantee. It is fixed by **either** making
the claim true (§4) **or** narrowing the documented claim (§5). Both are
acceptable; they are not mutually exclusive (narrow the docs now, tighten
enforcement over the next release).

---

## 4. Proposed enforcement design (if tightening)

One coherent policy check at one chokepoint. Two new capability axes, both bits
in the existing metadata, both default-deny.

### 4.1 Capability model

Treat usage as a small **capability set**, not independent booleans. Add, in the
**free `whNvmFlags` bits (12–15)** or — if more room is wanted — a new metadata
field (see §6 migration note):

1. **Algorithm/mode binding.** Bind the key to a *cipher capability*, not just a
   direction. The minimum that closes §2.3 is a flag that marks a symmetric key
   as **AEAD-only** (GCM), forbidding ECB/CBC/CTR/CMAC over the same key — i.e.
   "a key bound to GCM can do nothing else." Default-deny: enumerate *allowed*
   capabilities, never *forbidden pairs*.
2. **Managed-vs-explicit nonce** (see §4.3): whether the key may be driven with a
   client-supplied IV at all, or only via the server-managed-nonce path.

Direction (encrypt/decrypt) and wrap/derive already exist and stay.

### 4.2 Single dispatch chokepoint

The dispatch switch (`src/wh_server_crypto.c:5089-5126`) already has both
discriminators in scope at one point: `action` (`WC_ALGO_TYPE_CIPHER` /
`_CMAC` / `_PK`) and `rqstHeader.algoType` (`WC_CIPHER_AES_ECB`/`_CBC`/`_CTR`/
`_GCM`). Introduce one helper, called once per request *before* the per-mode
handler runs:

```
wh_Server_KeystoreEnforceKeyPolicy(server, keyId,
                                   requested_algo,   /* from action+algoType */
                                   requested_dir,    /* enc/dec */
                                   nonce_mode)       /* managed/explicit */
```

It resolves the key once, checks direction (existing bits) **and** that
`requested_algo` is within the key's bound capability set **and** that
`nonce_mode` is permitted. The per-mode handlers keep their existing inline check
during transition (defence in depth) but the chokepoint becomes the authority.
The design invariant: **no path to a cipher primitive that does not pass through
this check.**

### 4.3 Server-managed-nonce AES-GCM path (closes §2.4)

Mirror the wrap path that already exists:

- **Encrypt:** no client IV input. Server generates the nonce
  (`wc_RNG_GenerateBlock(server->crypto->rng, ...)`, as
  `src/wh_server_keystore.c:1204` already does) and **returns it** with the
  ciphertext+tag.
- **Decrypt:** IV is an input (supplied back by the client). This asymmetry is
  correct — a reused/chosen IV at *decrypt* does not enable the encryption-side
  games.
- Make **managed-nonce a key capability** (axis 2 above). Withheld keys get
  managed-nonce-only and physically cannot be driven with an explicit IV;
  "discouragement" is not enough against a malicious client.
- **Nonce-collision bound is load-bearing and must be written down per key
  class.** Random 96-bit nonces have a birthday bound (~2^-32 after ~2^32
  messages per key). Acceptable for occasional config writes; for high-volume
  keys use a deterministic counter with **durable, atomic, monotonic** state, or
  enforce a documented per-key message cap. Note the reboot/multi-core reuse risk
  for any counter that is not durable.

Fixes 2 and 3 are the **same mechanism** — managed-vs-explicit nonce is just
another capability bit — and should be built together.

---

## 5. Proposed documentation change (if narrowing instead/also)

If enforcement is not tightened immediately, the docs must stop implying the
withheld-key-vs-malicious-client guarantee for symmetric keys. Concretely, in
`docs/src/5-Features.md` Key Usage Policies (`:361-389`):

- State that usage flags are **direction/role** controls, **not algorithm/mode
  isolation**: a `USAGE_ENCRYPT` symmetric key may be used under *any* enabled
  AES mode, including raw ECB, over the same key bytes.
- State explicitly that exposing a symmetric encryption key to an untrusted
  client lets that client extract GCM authority (`H`, per-nonce `E_K(J0)`,
  keystream) for that key even though the key bytes never leave — so
  `NONEXPORTABLE` protects bytes, not authority.
- Record the **self-scoped carve-out** (Fix 1): exposing a GCM key to its caller
  is safe **only when the key's authority is self-scoped to that caller** (e.g. a
  per-session TLS traffic key, whose plaintext the caller already holds). List
  the invalidating conditions: the key (or a client-drivable deterministic
  derivative) is reused across clients/sessions; the key later wraps/protects
  material other clients consume; or an "offloading" change shifts the boundary.
  Write it as a deliberate assumption so future work re-tests it.

---

## 6. Migration / scope notes

- `whNvmMetadata` is a **fixed 32-byte, raw-`memcpy` format** in NVM *and* in
  wrapped blobs. Using the **free flag bits 12–15** avoids a struct-size change
  and is backward compatible (old keys read back with the new bits clear). But
  "clear" means "no new capability" — under default-deny that is the *safe*
  direction (old keys simply won't get the new managed-nonce/AEAD-only
  capabilities until re-provisioned). Confirm no existing logic treats the high
  bits as reserved-must-be-zero in a way that rejects old keys.
- Adding a whole new metadata field (rather than reusing flag bits) is a real
  format/migration change touching NVM layout, the wrapped-blob layout, and the
  keystore message structs — scope accordingly. Reusing flag bits is strongly
  preferred for the first increment.
- The server-managed-nonce GCM path needs a **new request/response message
  type** (no IV-in on encrypt, IV-out added) in `wh_message_crypto.h` plus client
  API — additive, no break to the existing explicit-IV path (which remains for
  self-scoped keys).

---

## 7. Recommended decision points (for maintainers)

1. **Question A:** commit to (or explicitly decline) the malicious-client model
   for withheld symmetric keys. This gates whether §4 ships.
2. **Claims fix direction:** §4 (tighten), §5 (narrow docs), or both-phased.
   Shipping neither leaves the leaky implied guarantee standing.
3. If tightening: confirm the first increment is **AEAD-only + managed-nonce
   capability bits in the free flag range**, enforced at a **single dispatch
   chokepoint**, with the existing per-handler checks retained during transition.
4. Write down the **per-key-class nonce bound** and the **self-scoped carve-out**
   regardless of which path is chosen.

---

## Appendix — verification caveats

The cryptographic analysis is standard and codebase-independent. The
wolfHSM-specific claims above were each checked against source at the cited
locations. Two items to re-verify before relying on them for a shipping decision:
the DRBG's FIPS/validation status for server-generated nonces, and the exact
validated-boundary reasoning for any TLS-offload scenario (not covered by this
review).
