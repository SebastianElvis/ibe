# Boneh-Franklin Identity-Based Encryption Specification

## 1. Overview

This document specifies the Boneh-Franklin Identity-Based Encryption (IBE) scheme
as implemented in this crate, adapted from the original paper:

> Dan Boneh and Matthew Franklin. "Identity-Based Encryption from the Weil Pairing."
> SIAM Journal on Computing, 32(3):586-615, 2003.

The implementation targets the **BN254** pairing-friendly elliptic curve and provides
two scheme variants:

- **BasicIdent**: IND-ID-CPA secure (chosen-plaintext security).
- **FullIdent**: IND-ID-CCA secure (chosen-ciphertext security) via the Fujisaki-Okamoto transform.

**Security level**: ~100 bits (due to the exTNFS attack on BN254; see Section 7).

## 2. Notation and Preliminaries

### 2.1 Groups

| Symbol | Description |
|--------|-------------|
| G1 | Additive group of BN254 G1 points (over Fq) |
| G2 | Additive group of BN254 G2 points (over Fq2) |
| GT | Multiplicative target group of the pairing (subgroup of Fq12*) |
| Fr | Scalar field (order of G1, G2, GT) |
| Fq | Base field of BN254 |
| e | Optimal Ate pairing: G1 x G2 -> GT |
| P | Fixed generator of G2 (BN254 standard generator) |

### 2.2 Asymmetric Pairing Adaptation

The original Boneh-Franklin paper uses a **symmetric** pairing `e: G x G -> GT`.
BN254 provides an **asymmetric** pairing `e: G1 x G2 -> GT`. We adapt as follows:

- System generator `P` is in **G2**
- Public key `P_pub = s * P` is in **G2**
- Identity hash `Q_ID = H1(ID)` maps to **G1**
- Private key `d_ID = s * Q_ID` is in **G1**
- Ciphertext component `U = r * P` is in **G2**

**Correctness**: `e(d_ID, U) = e(s*Q_ID, r*P) = e(Q_ID, P)^{sr} = e(Q_ID, s*P)^r = e(Q_ID, P_pub)^r`

### 2.3 BN254 Curve Parameters

- Curve equation (G1): `y^2 = x^3 + 3` over Fq
- Embedding degree: 12
- Scalar field order q: ~254 bits
- Base field order p: ~254 bits
- Cofactor (G1): 1

## 3. Hash Functions

All hash functions use SHA-256 as the underlying primitive with domain separation.

### 3.1 H1: Identity to G1 Point

```
H1: {0,1}* -> G1
```

**Method**: Try-and-increment (hash-and-check).

**Algorithm**:
1. Let DST = `"IBE-BN254-H1"` (13 bytes)
2. For counter = 0, 1, 2, ..., 255:
   a. Compute `h = SHA-256(DST || identity || counter_le32)`
   b. Interpret `h` as an element `x` in Fq via `Fq::from_le_bytes_mod_order(h)`
   c. Compute `rhs = x^3 + 3` in Fq
   d. If `rhs` is a quadratic residue in Fq:
      - Compute `y = sqrt(rhs)` (take the lexicographically smaller root)
      - Construct point `(x, y)` in G1
      - Verify the point is on the curve and in the correct subgroup
      - Return the point
3. If no valid point found after 256 iterations, return error.

**Note**: This method is NOT constant-time with respect to the identity. This is
acceptable because identities are public in IBE. H1 MUST only be called on
public inputs.

### 3.2 H2: GT Element to Byte Mask

```
H2: GT x N -> {0,1}^n
```

**Method**: Counter-mode SHA-256 KDF.

**Algorithm**:
1. Serialize the GT element (Fq12 value) using arkworks canonical compressed serialization
2. For each 32-byte block `i = 0, 1, 2, ...`:
   - Compute `block_i = SHA-256(0x02 || serialized_gt || i_le32)`
3. Concatenate blocks and truncate to `n` bytes

### 3.3 H3: (Sigma, Message) to Scalar

```
H3: {0,1}^n x {0,1}* -> Fr
```

**Used only in FullIdent.**

**Algorithm**:
1. Compute `h = SHA-256(0x03 || len(sigma)_le64 || sigma || message)`
2. Interpret `h` as an element of Fr via `Fr::from_le_bytes_mod_order(h)`

The length prefix on sigma prevents ambiguity when sigma and message are concatenated.

### 3.4 H4: Sigma to Message Mask

```
H4: {0,1}^n x N -> {0,1}^m
```

**Used only in FullIdent.**

**Method**: Counter-mode SHA-256 (same structure as H2 with domain tag `0x04`).

**Algorithm**:
1. For each 32-byte block `i = 0, 1, 2, ...`:
   - Compute `block_i = SHA-256(0x04 || sigma || i_le32)`
2. Concatenate blocks and truncate to `m` bytes

## 4. BasicIdent Scheme

### 4.1 Setup

**Input**: Security parameter (implicit: BN254 curve choice)

**Output**: System parameters `params`, master secret key `msk`

**Algorithm**:
1. Let `P = G2::generator()` (standard BN254 G2 generator)
2. Choose random `s <- Fr`
3. Compute `P_pub = s * P` in G2
4. Set `params = (P, P_pub)` with default block size `n = 32`
5. Set `msk = s`
6. Return `(params, msk)`

### 4.2 Extract

**Input**: Master secret key `msk = s`, identity `ID`

**Output**: Private key `d_ID`

**Algorithm**:
1. Compute `Q_ID = H1(ID)` in G1
2. Compute `d_ID = s * Q_ID` in G1
3. Return `d_ID`

### 4.3 Encrypt

**Input**: System parameters `params`, identity `ID`, message `M` (at most `n` bytes)

**Output**: Ciphertext `C = (U, V)`

**Algorithm**:
1. Pad `M` to `n` bytes (zero-padded): `M' = M || 0^{n - |M|}`
2. Compute `Q_ID = H1(ID)` in G1
3. Choose random `r <- Fr`
4. Compute `U = r * P` in G2
5. Compute `g_ID = e(Q_ID, P_pub)` in GT
6. Compute `g_ID_r = g_ID^r` in GT (scalar multiplication in the target group)
7. Compute `mask = H2(g_ID_r, n)`
8. Compute `V = M' XOR mask`
9. Return `C = (U, V)`

### 4.4 Decrypt

**Input**: System parameters `params`, private key `d_ID`, ciphertext `C = (U, V)`

**Output**: Padded message `M'` (n bytes)

**Algorithm**:
1. Verify `|V| = n`, else return error
2. Compute `pairing_val = e(d_ID, U)` in GT
3. Compute `mask = H2(pairing_val, n)`
4. Compute `M' = V XOR mask`
5. Return `M'`

**Note**: The caller is responsible for removing zero-padding to recover the original
message length.

## 5. FullIdent Scheme

FullIdent uses the Fujisaki-Okamoto transform to achieve IND-ID-CCA security.
It supports arbitrary-length messages.

### 5.1 Setup and Extract

Same as BasicIdent (Sections 4.1 and 4.2).

### 5.2 Encrypt

**Input**: System parameters `params`, identity `ID`, message `M` (arbitrary length)

**Output**: Ciphertext `C = (U, V, W)`

**Algorithm**:
1. Compute `Q_ID = H1(ID)` in G1
2. Choose random `sigma <- {0,1}^n` (random n-byte string)
3. Compute `r = H3(sigma, M)` in Fr (deterministic randomness)
4. Compute `U = r * P` in G2
5. Compute `g_ID = e(Q_ID, P_pub)` in GT
6. Compute `g_ID_r = g_ID^r` in GT
7. Compute `V = sigma XOR H2(g_ID_r, n)`
8. Compute `W = M XOR H4(sigma, |M|)`
9. Return `C = (U, V, W)`

### 5.3 Decrypt

**Input**: System parameters `params`, private key `d_ID`, ciphertext `C = (U, V, W)`

**Output**: Message `M` or error

**Algorithm**:
1. Verify `|V| = n`, else return error
2. Compute `pairing_val = e(d_ID, U)` in GT
3. Compute `sigma = V XOR H2(pairing_val, n)`
4. Compute `M = W XOR H4(sigma, |W|)`
5. **CCA Verification**:
   a. Compute `r' = H3(sigma, M)` in Fr
   b. Compute `U' = r' * P` in G2
   c. If `U' != U`, return `DecryptionVerificationFailed` error
6. Return `M`

The verification step (5) is critical for CCA security. It ensures that the
ciphertext was honestly constructed. Any tampering with U, V, or W will cause
this check to fail with overwhelming probability.

## 6. Serialization Format

All serialization uses arkworks `CanonicalSerialize` with compressed mode.

### 6.1 PublicParams

```
[generator: G2Affine compressed] [public_key: G2Affine compressed]
```

G2 affine compressed: 64 bytes (BN254).

Total: 128 bytes.

### 6.2 PrivateKey

```
[d_id: G1Affine compressed]
```

G1 affine compressed: 32 bytes (BN254).

Total: 32 bytes.

### 6.3 BasicCiphertext

```
[u: G2Affine compressed] [v_len: u64 LE] [v: v_len bytes]
```

Maximum v_len: 1,048,576 bytes (1 MB limit to prevent OOM on deserialization).

### 6.4 FullCiphertext

```
[u: G2Affine compressed] [v_len: u64 LE] [v: v_len bytes] [w_len: u64 LE] [w: w_len bytes]
```

Maximum v_len, w_len: 1,048,576 bytes each.

## 7. Security Considerations

### 7.1 Security Level

BN254 provides approximately **100-bit security** against the best known attacks
(Kim-Barbulescu exTNFS). This is below the commonly recommended 128-bit level.
Deployments requiring 128-bit security should consider BLS12-381 instead.

### 7.2 Security Model

Both schemes are proven secure in the **Random Oracle Model** (ROM):

- **BasicIdent**: IND-ID-CPA secure under the Bilinear Diffie-Hellman (BDH) assumption.
- **FullIdent**: IND-ID-CCA secure under BDH in the ROM (via Fujisaki-Okamoto transform).

### 7.3 H1 Timing Side-Channel

The try-and-increment method for H1 has variable execution time depending on the
identity input. Since identities are public information in IBE, this does not
constitute a vulnerability. However, H1 MUST NOT be used to hash secret values.

### 7.4 Key Material Protection

- `MasterSecretKey` implements `Zeroize` and `ZeroizeOnDrop` to clear the scalar
  from memory when the value is dropped.
- `PrivateKey` overwrites its curve point on drop.
- The master secret key MUST be stored and transmitted securely. Its compromise
  allows derivation of all private keys in the system.

### 7.5 Randomness Requirements

- `Setup` and `BasicIdent::encrypt` require a cryptographically secure RNG.
- `FullIdent::encrypt` uses a random sigma which is then converted to deterministic
  randomness via H3. The initial sigma MUST be generated from a CSPRNG.

### 7.6 Deserialization Safety

All deserialization functions enforce a maximum byte vector length of 1 MB to
prevent memory exhaustion attacks from malicious inputs. Curve points are validated
to be on the curve and in the correct subgroup during deserialization.

## 8. References

1. D. Boneh, M. Franklin. "Identity-Based Encryption from the Weil Pairing."
   SIAM J. Computing, 32(3):586-615, 2003. https://crypto.stanford.edu/~dabo/papers/bfibe.pdf

2. E. Fujisaki, T. Okamoto. "Secure Integration of Asymmetric and Symmetric
   Encryption Schemes." CRYPTO 1999.

3. IETF RFC 5091. "Identity-Based Cryptography Standard (IBCS) #1."
   https://datatracker.ietf.org/doc/html/rfc5091

4. IETF RFC 5409. "Using the Boneh-Franklin and Boneh-Boyen IBE with CMS."
   https://www.rfc-editor.org/rfc/rfc5409/

5. arkworks contributors. "arkworks: An Ecosystem for zkSNARK Programming."
   https://github.com/arkworks-rs

6. IETF RFC 9380. "Hashing to Elliptic Curves."
   https://datatracker.ietf.org/doc/rfc9380/
