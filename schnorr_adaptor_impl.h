#ifndef SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorrsig.h"
#include "../../hash.h"

#include "schnorr_adaptor.h"


//---------|
// This function takes in the nonce r(in jacobian coordinates) and performs point addition with adaptor point(in affine coordinates) and then finally serializes 
// the tweaked nonce into a 32 byte array.
static void secp256k1_schnorr_adaptor_tweak_nonce_and_serialize(unsigned char *fin_nonce, secp256k1_gej *rj, secp256k1_ge *adaptorp){
    secp256k1_ge fin_nonce_pt;
    secp256k1_gej fin_nonce_ptj;
    // fin_nonce = R + T
    secp256k1_gej_add_ge_var(&fin_nonce_ptj, &rj, &adaptorp, NULL);
    secp256k1_ge_set_gej(&fin_nonce_pt, &fin_nonce_ptj);
    if (secp256k1_ge_is_infinity(&fin_nonce_pt)){
        fin_nonce_pt = secp256k1_ge_const_g;
    }
    ret = secp256k1_xonly_ge_serialize(fin_nonce, &fin_nonce_pt);
    VERIFY_CHECK(ret);

/** 
 *  Will, include this later after finding the most efficient way to store nonce_parity for the adapt and extract algorithms.
 *  secp256k1_fe_normalize_var(&fin_nonce_pt.y);
 *  *fin_nonce_parity = secp256k1_fe_is_odd(&fin_nonce_pt.y);
 */
}
//---------||

int secp256k1_schnorr_adaptor_sign(const secp256k1_context *ctx, unsigned char *pre_sig64, const unsigned char *msg, const secp256k1_keypair *keypair, const secp256k1_pubkey *adaptor){
    secp256k1_scalar sk;
    secp256k1_scalar e;
    secp256k1_scalar k;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_ge r;

    //---------|
    secp256k1_ge adaptorp;
    unsigned char fin_nonce[32];
    //---------||

    unsigned char buf[32] = {0};
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(pre_sig64 != NULL);
    ARG_CHECK(msg != NULL);
    ARG_CHECK(keypair != NULL);
    //---------|
    ARG_CHECK(adaptor != NULL);
    //---------||

    if (noncefp == NULL){
        noncefp = secp256k1_nonce_function_bip340;
    }

    ret &= secp256k1_keypair_load(ctx, &sk, &pk, keypair);
    if (secp256k1_fe_is_odd(&pk.y)){
        secp256k1_scalar_negate(&sk, &sk);
    }

    secp256k1_scalar_get_b32(seckey, &sk);
    secp256k1_fe_get_b32(pk_buf, &pk.x);
    ret &= !!noncefp(buf, msg, 32, seckey, pk_buf, bip340_algo, sizeof(bip340_algo), ndata);
    secp256k1_scalar_set_b32(&k, buf, NULL);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej(&r, &rj);

    secp256k1_declassify(ctx, &r, sizeof(r));
    secp256k1_fe_normalize_var(&r.y);
    if (secp256k1_fe_is_odd(&r.y)){
        secp256k1_scalar_negate(&k, &k);
    }
    secp256k1_fe_normalize_var(&r.x);

    secp256k1_fe_get_b32(&pre_sig64[0], &r.x);

    //---------|
    //Load the value of pubkey type adaptor into group element adaptorp.
    if (!secp256k1_pubkey_load(ctx, &adaptorp, adaptor)){
        return 0;
    }

    // Tweak the nonce rj with the adaptorp for the challenge part e := H(R+T||P||m) 
    secp256k1_schnorr_adaptor_tweak_nonce_and_serialize(fin_nonce, &rj, &adaptorp);

    // Compute e := H(R+T||P||m)
    secp256k1_schnorrsig_challenge(&e, fin_nonce, msg, 32, pk_buf);
    //---------||

    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(&pre_sig64[32], &e);

    secp256k1_memczero(pre_sig64, 64, !ret);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);
    memset(seckey, 0, sizeof(seckey));

    return ret;
}

int secp256k1_schnorr_adaptor_verify(const secp256k1_context *ctx, const unsigned char *pre_sig64, const unsigned char *msg, const secp256k1_xonly_pubkey *pubkey, const secp256k1_pubkey *adaptor){
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_gej pkj;
    secp256k1_fe rx;
    secp256k1_ge r;
    unsigned char buf[32];
    int overflow;
    //---------|
    secp256k1_ge adaptorp;
    unsigned char fin_nonce[32];
    secp256k1_ge r1;
    secp256k1_gej r1j;
    secp256k1_xonly_pubkey xonly_r1;
    //---------||

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pre_sig64 != NULL);
    ARG_CHECK(msg != NULL);
    ARG_CHECK(pubkey != NULL);
    //---------
    ARG_CHECK(adaptor != NULL)
    //---------

    if (!secp256k1_fe_set_b32(&rx, &pre_sig64[0])){
        return 0;
    }

    secp256k1_scalar_set_b32(&s, &pre_sig64[32], &overflow);
    if (overflow){
        return 0;
    }

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey)){
        return 0;
    }

    //---------
    //Parse the available x-coordinate of r into a public key.
    if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_r1, &pre_sig64[0])){
        return 0;
    }

    //Load the parsed public key into a group element r1.
    if (!secp256k1_xonly_pubkey_load(ctx, &r1, &xonly_r1)){
        return 0;
    }

    //Load the value of pubkey type adaptor into group element adaptorp.
    if (!secp256k1_pubkey_load(ctx, &adaptorp, adaptor)){
        return 0;
    }

    //Convert affine coordinates to jacobian to perform much precise point addition.
    secp256k1_gej_set_ge(&r1j,&r1);
    // Tweak the nonce rj with the adaptorp for the challenge part e := H(R+T||P||m) 
    secp256k1_schnorr_adaptor_tweak_nonce_and_serialize(fin_nonce, &r1j, &adaptorp);

    secp256k1_fe_get_b32(buf, &pk.x);
    //Compute e := H(R+T||P||m)
    secp256k1_schnorrsig_challenge(&e, fin_nonce, msg, 32, pk_buf);
    //---------

    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&pkj, &pk);
    secp256k1_ecmult(&rj, &pkj, &e, &s);

    secp256k1_ge_set_gej_var(&r, &rj);
    if (secp256k1_ge_is_infinity(&r)){
        return 0;
    }

    secp256k1_fe_normalize_var(&r.y);
    return !secp256k1_fe_is_odd(&r.y) &&
           secp256k1_fe_equal_var(&rx, &r.x);
}

int secp256k1_schnorr_adaptor_adapt(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *pre_sig64, const unsigned char *sec_adaptor32, int nonce_parity) {
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pre_sig64 != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);
    ARG_CHECK(nonce_parity == 0 || nonce_parity == 1);

    secp256k1_scalar_set_b32(&s, &pre_sig64[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&t, sec_adaptor32, &overflow);
    ret &= !overflow;

    /* Determine if the secret adaptor should be negated.
     *
     * Since a BIP340 signature requires an x-only public nonce, in the case where
     * (r + t)*G has odd Y-coordinate (i.e. nonce_parity == 1), the x-only public nonce
     * corresponding to the signature is actually (-r - t)*G. Thus adapting a
     * pre-signature requires negating t in this case.
     */
    if (nonce_parity) {
        secp256k1_scalar_negate(&t, &t);
    }

    secp256k1_scalar_add(&s, &s, &t);
    secp256k1_scalar_get_b32(&sig64[32], &s);
    memmove(sig64, pre_sig64, 32);
    secp256k1_scalar_clear(&t);
    return ret;
}

int secp256k1_schnorr_adaptor_extract(const secp256k1_context* ctx, unsigned char *sec_adaptor32, const unsigned char *sig64, const unsigned char *pre_sig64, int nonce_parity) {
    secp256k1_scalar t;
    secp256k1_scalar s;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pre_sig64 != NULL);
    ARG_CHECK(nonce_parity == 0 || nonce_parity == 1);

    secp256k1_scalar_set_b32(&t, &sig64[32], &overflow);
    ret &= !overflow;
    secp256k1_scalar_negate(&t, &t);

    secp256k1_scalar_set_b32(&s, &pre_sig64[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_add(&t, &t, &s);

    if (!nonce_parity) {
        secp256k1_scalar_negate(&t, &t);
    }
    secp256k1_scalar_get_b32(sec_adaptor32, &t);
    secp256k1_scalar_clear(&t);
    return ret;
}

#endif
