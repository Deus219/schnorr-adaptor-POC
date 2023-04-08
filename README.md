# Schnorr Adaptor Proof Of Concept

This repository contains a proof of concept implementation of the Schnorr Adaptor Signature Scheme. The Schnorr Adaptor Signature Scheme is a cryptographic algorithm that can be used for various applications, such as atomic swaps, payment channels, and more. This implementation is based on combining my intuitions with the existing musig and schnorrsig modules in the libsecp256-zkp repo.

**Note**: Although I made an effort to match this module's design as closely as possible to the secp256k1-zkp repo, I had to make a few adjustments to streamline this poc's implementation. The final implementation will certainly fix all those minor design flaws.

## Schnorr Adaptor Signatures

### Generate:

The pre-signing algorithm of `schnorr_adaptor_sign` can be described as:

**Input**:
- `ctx`: a pointer to a secp256k1 context object.
- `pre_sig64`: a pointer to a 64-byte buffer that will hold the resulting Schnorr pre-signature.
- `msg`: a pointer to the message data to be signed.
- `keypair`: a pointer to a secp256k1 keypair object representing the signing key.
- `adaptor`: a pointer to an adaptor point encoded as a public key.

**Output**:
- Returns 1 if the pre-signature is succesfully generated, 0 otherwise.

**Steps**:
1. Verify that the `ctx` object is not NULL and that the *ecmult_gen* context is built.
2. Verify that the `pre_sig64` , `keypair` , `msg` and `adaptor` pointers are not NULL.
3. Load the secret key (`sk`) and public key (`pk`) from the keypair object using `secp256k1_keypair_load`.
4. If the y-coordinate of the public key is odd, negate the secret key.
5. Convert the secret key (`sk`) to a 32-byte array `seckey` using `secp256k1_scalar_get_b32`.
6. Convert the x-coordinate of the public key (`pk`) to a 32-byte array `pk_buf` using `secp256k1_fe_get_b32`.
7. Generate a nonce value `k`.
8. If `k` is zero, set it to one to avoid invalid signatures.
9. Compute the elliptic curve point `r` corresponding to the nonce value `k` using `secp256k1_ecmult_gen`.
10. Normalize and serialize the x-coordinate of `r` (`r.x`)to the first 32 bytes of the signature buffer `pre_sig64`.
11. Load the adaptor point (`adaptorp`) from the public key object `adaptor` using `secp256k1_pubkey_load`.
12. Tweak the nonce point `r` with the adaptor point `adaptorp`.
13. Negate `k` if the tweaked nonce has an odd ordinate.
14. Calculate the Schnorr signature challenge value `e` using `secp256k1_schnorrsig_challenge`.
15. Calculate the scalar value `e * sk + k` and serialize it to the remaining 32 bytes of `pre_sig64`.
16. Clear the `k` and `sk` scalar values and the `seckey` buffer from memory for security.
17. Return 1 if the signature was successfully generated, 0 otherwise.

### Verify:

The verification algorithm of `schnorr_adaptor_verify` can be described as:

**Input**:

- `ctx`: a pointer to a secp256k1 context object.
- `pre_sig64`: a pointer to a 64-byte buffer containing the Schnorr signature to be verified.
- `msg`: a pointer to the message data that was signed.
- `pubkey`: a pointer to a secp256k1 x-only public key object representing the verifying key.
- `adaptor`: a pointer to an adaptor point encoded as a public key.

**Output**:

- Returns 1 if the pre-signature is valid, 0 otherwise.

**Steps**:

1. Verify that the `ctx` object is not NULL.
2. Verify that the `pre_sig64` , `pubkey` , `msg` and `adaptor` pointers are not NULL.
3. Load the x-only public key (`pk`) from the `pubkey` object using `secp256k1_xonly_pubkey_load`.
4. Deserialize the first 32 bytes of `pre_sig64` into a field element `rx` using `secp256k1_fe_set_b32`.
5. Deserialize the second 32 bytes of `pre_sig64` into a scalar `s` using `secp256k1_scalar_set_b32`.
6. Parse and load the first 32 bytes of `pre_sig64` into a group element `r1`.
7. Load the adaptor point (`adaptorp`) from the public key object `adaptor` using `secp256k1_pubkey_load`.
8. Tweak the nonce point `r` with the adaptor point `adaptorp`.
9. Calculate the Schnorr signature challenge value `e` using `secp256k1_schnorrsig_challenge`.
10. Negate `e` to obtain `-e`.
11. Compute the elliptic curve point `rj = s*G + (-e)*pkj` using `secp256k1_ecmult`, where `G` is the generator point and `pkj` is the Jacobian form of `pk`.
12. Convert `rj` to affine form `r` using `secp256k1_ge_set_gej_var`.
13. If `r` is the point at infinity, the signature is invalid. Return 0.
14. Normalize the y-coordinate of `r` using `secp256k1_fe_normalize_var`.
15. If the y-coordinate of `r` is odd, the signature is invalid. Return 0.
16. Compare the x-coordinate of `r` (`r.x`) with `rx`. If they are equal, the signature is valid. Return 1. Otherwise, the signature is invalid. Return 0.

### Adapt:

Inputs:

- `ctx`: a pointer to a secp256k1 context object.
- `sig64`: a pointer to a 64-byte buffer that will hold the resulting adapted Schnorr signature.
- `pre_sig64`: a pointer to a 64-byte buffer containing the pre-signature.
- `sec_adaptor32`: a pointer to a 32-byte buffer containing the secret adaptor value.
- `nonce_parity`: an integer value indicating whether the adaptor signature needs to be negated.

Outputs:

- Returns 1 if the adaptation is successful, 0 otherwise.

Steps:

1. Verify that the `ctx` object is not NULL.
2. Verify that the `sig64`, `pre_sig64`, and `sec_adaptor32` pointers are not NULL, and that `nonce_parity` is either 0 or 1.
3. Convert the scalar `s` from the pre-existing signature `pre_sig64` to a scalar `s` using `secp256k1_scalar_set_b32`.
4. If the conversion overflows, return 0.
5. Convert the scalar `t` from the adaptor signature `sec_adaptor32` to a scalar `t` using `secp256k1_scalar_set_b32`.
6. If the conversion overflows, set `ret` to 0.
7. If `nonce_parity` is 1, negate the scalar `t` using `secp256k1_scalar_negate`.
8. Add the scalars `s` and `t` using `secp256k1_scalar_add`.
9. Convert the resulting scalar `s` to a 32-byte buffer and store it in the second 32 bytes of `sig64` using `secp256k1_scalar_get_b32`.
10. Copy the first 32 bytes of the pre-existing signature `pre_sig64` to the first 32 bytes of the new signature `sig64` using `memmove`.
11. Clear the scalar `t` using `secp256k1_scalar_clear`.
12. Return `ret`.

### Extract

Inputs:

- `ctx`: a pointer to a secp256k1 context object.
- `sec_adaptor32`: a pointer to a 32-byte buffer that will hold the secret adaptor value.
- `sig64`: a pointer to a 64-byte buffer containing the Schnorr signature.
- `pre_sig64`: a pointer to a 64-byte buffer containing the Schnorr pre-signature.
- `nonce_parity`: an integer value indicating whether the adaptor signature was negated during adaptation.

Outputs:

- Returns 1 if the extraction is successful, 0 otherwise.

Steps:

1. Verify that the `ctx` object is not NULL.
2. Verify that the `sec_adaptor32`, `sig64`, and `pre_sig64` pointers are not NULL, and that `nonce_parity` is either 0 or 1.
3. Convert the scalar `t` from the second 32 bytes of `sig64` to a scalar using `secp256k1_scalar_set_b32`.
4. If the conversion overflows, set `ret` to 0.
5. Negate the scalar `t` using `secp256k1_scalar_negate`.
6. Convert the scalar `s` from the pre-existing signature `pre_sig64` to a scalar `s` using `secp256k1_scalar_set_b32`.
7. If the conversion overflows, return 0.
8. Add the scalars `t` and `s` using `secp256k1_scalar_add`.
9. If `nonce_parity` is 0, negate the scalar `t` using `secp256k1_scalar_negate`.
10. Convert the resulting scalar `t` to a 32-byte buffer and store it in `sec_adaptor32` using `secp256k1_scalar_get_b32`.
11. Clear the scalar `t` using `secp256k1_scalar_clear`.
12. Return `ret`.

## Correctness and Security

Mathematical formulations and proofs behind schnorr adaptor signatur's correctness and security definitions such as aEU-CMF, pre-signature adaptability and witness extractability can be found [here](https://eprint.iacr.org/2020/476.pdf) - a research paper titled “Generalized Channels from Limited Blockchain Scripts and Adaptor Signatures” published in 2020 under International Association for Cryptologic Research (IACR).

## Checklist

Figure out the following things before the final implementation:

- [ ] Make sure all the nonce and hash related functions are included
- [ ] Extend support to variable length messages
- [ ] Refine and standardize `tweak_nonce_process` 
- [ ] `xonly_ge_serialize` is included or implemented again
- [ ] Efficient way to store `nonce_parity`
- [ ] All the liberties taken during this poc implementation are validated

