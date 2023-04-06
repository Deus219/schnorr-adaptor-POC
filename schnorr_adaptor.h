#ifndef SECP256K1_SCHNORR_ADAPTOR_H
#define SECP256K1_SCHNORR_ADAPTOR_H


#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h" 

#ifdef __cplusplus
extern "C" {
#endif

/** Note:
 *  1. Functions/Structures related to nonce generation & hashing are not included in this draft
 *  because they are very similar to the ones used in Schnorrsig module. Will include
 *  them in the final implementation.
 *  2. This module currently supports only 32 byte messages will later extend support to variable
 *  length messages.
 *  3. For the adapt and extract algorithms, still couldn't figure out a way to efficiently 
 *  store nonce parity, so there might be a little confusion of their usage in this draft.
 *  4. Might have taken a few liberties as this isn't the final implementation.
 */

/** Create a Schnorr pre-signature.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:        ctx: pointer to a context object, initialized for signing.
 *  Out:   pre_sig64: pointer to a 64-byte array to store the serialized pre-signature.
 *      nonce_parity: pointer to store the parity of final nonce.
 *  In:        msg: the 32-byte message being signed.
 *           keypair: pointer to an initialized keypair.
 *           adaptor: pointer to an adaptor point encoded as a public key.
 */
SECP256K1_API int secp256k1_schnorr_adaptor_sign(
    const secp256k1_context* ctx,
    unsigned char *pre_sig64,
    const unsigned char *msg,
    const secp256k1_keypair *keypair,
    const secp256k1_pubkey *adaptor,
    int *nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify a Schnorr pre-signature.
 *
 *  Returns: 1: correct pre-signature
 *           0: incorrect pre-signature
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:pre_sig64: pointer to the 64-byte pre-signature to verify.
 *           msg: the message being verified.
 *        pubkey: pointer to an x-only public key to verify with.
 *       adaptor: pointer to an adaptor point encoded as a public key.
 */
SECP256K1_API int secp256k1_schnorr_adaptor_verify(
    const secp256k1_context* ctx,
    const unsigned char *pre_sig64,
    const unsigned char *msg,
    const secp256k1_xonly_pubkey *pubkey,
    const secp256k1_pubkey *adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Creates a signature from a pre-signature and an adaptor.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:         ctx: pointer to a context object
 *  Out:        sig64: 64-byte signature. 
 *  In:     pre_sig64: 64-byte pre-signature
 *      sec_adaptor32: 32-byte secret adaptor to add to the pre-signature
 *       nonce_parity: parity of the tweaked nonce
 */
SECP256K1_API int secp256k1_schnorr_adaptor_adapt(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char *pre_sig64,
    const unsigned char *sec_adaptor32,
    int nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extracts a secret adaptor from a Schnorr pre-signature and corresponding
 *  signature
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:         ctx: pointer to a context object
 *  Out:sec_adaptor32: 32-byte secret adaptor
 *  In:         sig64: complete, valid 64-byte signature
 *          pre_sig64: the pre-signature corresponding to sig64
 *       nonce_parity: parity of the tweaked nonce
 */
SECP256K1_API int secp256k1_schnorr_adaptor_extract(
    const secp256k1_context* ctx,
    unsigned char *sec_adaptor32,
    const unsigned char *sig64,
    const unsigned char *pre_sig64,
    int nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORR_ADAPTOR_H */
