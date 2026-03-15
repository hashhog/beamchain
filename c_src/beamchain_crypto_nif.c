/**
 * beamchain_crypto_nif.c — secp256k1 NIF bindings for Erlang
 *
 * Wraps libsecp256k1 for ECDSA/Schnorr signature verification
 * and public key operations. All functions run on dirty CPU schedulers
 * to avoid blocking the Erlang VM's normal schedulers.
 */

#include <string.h>
#include <erl_nif.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
#include <secp256k1_ellswift.h>

static secp256k1_context *ctx = NULL;

/* ------------------------------------------------------------------ */
/* NIF lifecycle                                                       */
/* ------------------------------------------------------------------ */

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    if (!ctx) return -1;
    return 0;
}

static void unload(ErlNifEnv *env, void *priv_data)
{
    if (ctx) {
        secp256k1_context_destroy(ctx);
        ctx = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM make_error(ErlNifEnv *env, const char *reason)
{
    return enif_make_tuple2(env,
        enif_make_atom(env, "error"),
        enif_make_atom(env, reason));
}

static ERL_NIF_TERM make_ok_binary(ErlNifEnv *env,
                                    const unsigned char *data, size_t len)
{
    ERL_NIF_TERM bin;
    unsigned char *buf = enif_make_new_binary(env, len, &bin);
    memcpy(buf, data, len);
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), bin);
}

/* ------------------------------------------------------------------ */
/* ecdsa_verify_nif(Msg32, DerSig, PubKey) -> true | false             */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM ecdsa_verify_nif(ErlNifEnv *env, int argc,
                                      const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg, sig, pubkey;

    if (!enif_inspect_binary(env, argv[0], &msg) ||
        !enif_inspect_binary(env, argv[1], &sig) ||
        !enif_inspect_binary(env, argv[2], &pubkey))
        return enif_make_badarg(env);

    if (msg.size != 32)
        return make_error(env, "invalid_msg_size");

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey.data, pubkey.size))
        return make_error(env, "invalid_pubkey");

    secp256k1_ecdsa_signature ecdsa_sig;
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &ecdsa_sig,
                                              sig.data, sig.size))
        return make_error(env, "invalid_signature");

    int result = secp256k1_ecdsa_verify(ctx, &ecdsa_sig, msg.data, &pk);
    return enif_make_atom(env, result ? "true" : "false");
}

/* ------------------------------------------------------------------ */
/* schnorr_verify_nif(Msg32, Sig64, XOnlyPubKey32) -> true | false     */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM schnorr_verify_nif(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg, sig, pubkey;

    if (!enif_inspect_binary(env, argv[0], &msg) ||
        !enif_inspect_binary(env, argv[1], &sig) ||
        !enif_inspect_binary(env, argv[2], &pubkey))
        return enif_make_badarg(env);

    if (msg.size != 32 || sig.size != 64 || pubkey.size != 32)
        return make_error(env, "invalid_size");

    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, pubkey.data))
        return make_error(env, "invalid_pubkey");

    int result = secp256k1_schnorrsig_verify(ctx, sig.data,
                                              msg.data, 32, &xpk);
    return enif_make_atom(env, result ? "true" : "false");
}

/* ------------------------------------------------------------------ */
/* pubkey_create_nif(SecKey32) -> {ok, PubKey33} | {error, reason}     */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_create_nif(ErlNifEnv *env, int argc,
                                       const ERL_NIF_TERM argv[])
{
    ErlNifBinary seckey;

    if (!enif_inspect_binary(env, argv[0], &seckey) || seckey.size != 32)
        return enif_make_badarg(env);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, seckey.data))
        return make_error(env, "invalid_seckey");

    unsigned char out[33];
    size_t out_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk,
                                  SECP256K1_EC_COMPRESSED);
    return make_ok_binary(env, out, 33);
}

/* ------------------------------------------------------------------ */
/* pubkey_tweak_add_nif(PubKey, Tweak32) -> {ok, PubKey33}             */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_tweak_add_nif(ErlNifEnv *env, int argc,
                                          const ERL_NIF_TERM argv[])
{
    ErlNifBinary pubkey_bin, tweak;

    if (!enif_inspect_binary(env, argv[0], &pubkey_bin) ||
        !enif_inspect_binary(env, argv[1], &tweak) || tweak.size != 32)
        return enif_make_badarg(env);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey_bin.data, pubkey_bin.size))
        return make_error(env, "invalid_pubkey");

    if (!secp256k1_ec_pubkey_tweak_add(ctx, &pk, tweak.data))
        return make_error(env, "tweak_failed");

    unsigned char out[33];
    size_t out_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk,
                                  SECP256K1_EC_COMPRESSED);
    return make_ok_binary(env, out, 33);
}

/* ------------------------------------------------------------------ */
/* xonly_pubkey_tweak_add_nif(XOnlyPK32, Tweak32)                      */
/*   -> {ok, OutputPK32, Parity} | {error, reason}                    */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM xonly_pubkey_tweak_add_nif(ErlNifEnv *env, int argc,
                                                const ERL_NIF_TERM argv[])
{
    ErlNifBinary pubkey_bin, tweak;

    if (!enif_inspect_binary(env, argv[0], &pubkey_bin) || pubkey_bin.size != 32 ||
        !enif_inspect_binary(env, argv[1], &tweak) || tweak.size != 32)
        return enif_make_badarg(env);

    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, pubkey_bin.data))
        return make_error(env, "invalid_pubkey");

    secp256k1_pubkey output_pk;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &output_pk, &xpk, tweak.data))
        return make_error(env, "tweak_failed");

    secp256k1_xonly_pubkey output_xpk;
    int parity;
    int ok = secp256k1_xonly_pubkey_from_pubkey(ctx, &output_xpk, &parity, &output_pk);
    if (!ok) return make_error(env, "xonly_conversion_failed");

    unsigned char out[32];
    secp256k1_xonly_pubkey_serialize(ctx, out, &output_xpk);

    ERL_NIF_TERM out_bin;
    unsigned char *buf = enif_make_new_binary(env, 32, &out_bin);
    memcpy(buf, out, 32);

    return enif_make_tuple3(env,
        enif_make_atom(env, "ok"),
        out_bin,
        enif_make_int(env, parity));
}

/* ------------------------------------------------------------------ */
/* pubkey_compress_nif(PubKey) -> {ok, Compressed33}                   */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_compress_nif(ErlNifEnv *env, int argc,
                                         const ERL_NIF_TERM argv[])
{
    ErlNifBinary pubkey_bin;

    if (!enif_inspect_binary(env, argv[0], &pubkey_bin))
        return enif_make_badarg(env);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey_bin.data, pubkey_bin.size))
        return make_error(env, "invalid_pubkey");

    unsigned char out[33];
    size_t out_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk,
                                  SECP256K1_EC_COMPRESSED);
    return make_ok_binary(env, out, 33);
}

/* ------------------------------------------------------------------ */
/* pubkey_decompress_nif(PubKey) -> {ok, Uncompressed65}               */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_decompress_nif(ErlNifEnv *env, int argc,
                                           const ERL_NIF_TERM argv[])
{
    ErlNifBinary pubkey_bin;

    if (!enif_inspect_binary(env, argv[0], &pubkey_bin))
        return enif_make_badarg(env);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey_bin.data, pubkey_bin.size))
        return make_error(env, "invalid_pubkey");

    unsigned char out[65];
    size_t out_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk,
                                  SECP256K1_EC_UNCOMPRESSED);
    return make_ok_binary(env, out, 65);
}

/* ------------------------------------------------------------------ */
/* pubkey_combine_nif([PubKey]) -> {ok, Combined33}                    */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_combine_nif(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[])
{
    unsigned int list_len;
    if (!enif_get_list_length(env, argv[0], &list_len) ||
        list_len < 2 || list_len > 1024)
        return enif_make_badarg(env);

    secp256k1_pubkey *pubkeys = enif_alloc(list_len * sizeof(secp256k1_pubkey));
    const secp256k1_pubkey **ptrs = enif_alloc(list_len * sizeof(secp256k1_pubkey *));

    ERL_NIF_TERM head, tail = argv[0];
    for (unsigned int i = 0; i < list_len; i++) {
        enif_get_list_cell(env, tail, &head, &tail);
        ErlNifBinary pk_bin;
        if (!enif_inspect_binary(env, head, &pk_bin) ||
            !secp256k1_ec_pubkey_parse(ctx, &pubkeys[i],
                                        pk_bin.data, pk_bin.size)) {
            enif_free(pubkeys);
            enif_free(ptrs);
            return make_error(env, "invalid_pubkey");
        }
        ptrs[i] = &pubkeys[i];
    }

    secp256k1_pubkey combined;
    int ret = secp256k1_ec_pubkey_combine(ctx, &combined, ptrs, list_len);
    enif_free(pubkeys);
    enif_free(ptrs);

    if (!ret)
        return make_error(env, "combine_failed");

    unsigned char out[33];
    size_t out_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &combined,
                                  SECP256K1_EC_COMPRESSED);
    return make_ok_binary(env, out, 33);
}

/* ------------------------------------------------------------------ */
/* ecdsa_sign_nif(Msg32, SecKey32) -> {ok, DerSig} | {error, reason}   */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM ecdsa_sign_nif(ErlNifEnv *env, int argc,
                                    const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg, seckey;

    if (!enif_inspect_binary(env, argv[0], &msg) || msg.size != 32 ||
        !enif_inspect_binary(env, argv[1], &seckey) || seckey.size != 32)
        return enif_make_badarg(env);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg.data, seckey.data, NULL, NULL))
        return make_error(env, "signing_failed");

    unsigned char der[72];
    size_t der_len = 72;
    secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig);

    return make_ok_binary(env, der, der_len);
}

/* ------------------------------------------------------------------ */
/* schnorr_sign_nif(Msg32, SecKey32, AuxRand32)                        */
/*   -> {ok, Sig64} | {error, reason}                                  */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM schnorr_sign_nif(ErlNifEnv *env, int argc,
                                      const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg, seckey, aux_rand;

    if (!enif_inspect_binary(env, argv[0], &msg) || msg.size != 32 ||
        !enif_inspect_binary(env, argv[1], &seckey) || seckey.size != 32 ||
        !enif_inspect_binary(env, argv[2], &aux_rand) || aux_rand.size != 32)
        return enif_make_badarg(env);

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
        return make_error(env, "invalid_seckey");

    unsigned char sig[64];
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg.data, &keypair,
                                      aux_rand.data))
        return make_error(env, "signing_failed");

    return make_ok_binary(env, sig, 64);
}

/* ------------------------------------------------------------------ */
/* seckey_tweak_add_nif(SecKey32, Tweak32)                             */
/*   -> {ok, TweakedKey32} | {error, reason}                           */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM seckey_tweak_add_nif(ErlNifEnv *env, int argc,
                                          const ERL_NIF_TERM argv[])
{
    ErlNifBinary seckey, tweak;

    if (!enif_inspect_binary(env, argv[0], &seckey) || seckey.size != 32 ||
        !enif_inspect_binary(env, argv[1], &tweak) || tweak.size != 32)
        return enif_make_badarg(env);

    /* copy seckey — secp256k1_ec_seckey_tweak_add modifies in place */
    unsigned char result[32];
    memcpy(result, seckey.data, 32);

    if (!secp256k1_ec_seckey_tweak_add(ctx, result, tweak.data))
        return make_error(env, "tweak_failed");

    return make_ok_binary(env, result, 32);
}

/* ------------------------------------------------------------------ */
/* ellswift_create_nif(SecKey32, AuxRand32)                            */
/*   -> {ok, EllSwift64} | {error, reason}                             */
/* Creates a 64-byte ElligatorSwift-encoded public key from a private  */
/* key. Used for BIP324 v2 transport key exchange.                     */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM ellswift_create_nif(ErlNifEnv *env, int argc,
                                         const ERL_NIF_TERM argv[])
{
    ErlNifBinary seckey, auxrand;

    if (!enif_inspect_binary(env, argv[0], &seckey) || seckey.size != 32 ||
        !enif_inspect_binary(env, argv[1], &auxrand) || auxrand.size != 32)
        return enif_make_badarg(env);

    unsigned char ell64[64];
    if (!secp256k1_ellswift_create(ctx, ell64, seckey.data, auxrand.data))
        return make_error(env, "invalid_seckey");

    return make_ok_binary(env, ell64, 64);
}

/* ------------------------------------------------------------------ */
/* ellswift_xdh_nif(EllA64, EllB64, SecKey32, Party)                   */
/*   -> {ok, SharedSecret32} | {error, reason}                         */
/* Computes ECDH shared secret using ElligatorSwift pubkeys.           */
/* Party: 0 if we are party A (initiator), 1 if party B (responder).  */
/* Uses BIP324 hash function for key derivation.                       */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM ellswift_xdh_nif(ErlNifEnv *env, int argc,
                                      const ERL_NIF_TERM argv[])
{
    ErlNifBinary ell_a, ell_b, seckey;
    int party;

    if (!enif_inspect_binary(env, argv[0], &ell_a) || ell_a.size != 64 ||
        !enif_inspect_binary(env, argv[1], &ell_b) || ell_b.size != 64 ||
        !enif_inspect_binary(env, argv[2], &seckey) || seckey.size != 32 ||
        !enif_get_int(env, argv[3], &party))
        return enif_make_badarg(env);

    unsigned char output[32];
    if (!secp256k1_ellswift_xdh(ctx, output,
                                ell_a.data, ell_b.data,
                                seckey.data, party,
                                secp256k1_ellswift_xdh_hash_function_bip324,
                                NULL))
        return make_error(env, "ecdh_failed");

    return make_ok_binary(env, output, 32);
}

/* ------------------------------------------------------------------ */
/* NIF table                                                           */
/* ------------------------------------------------------------------ */

static ErlNifFunc nif_funcs[] = {
    {"ecdsa_verify_nif",           3, ecdsa_verify_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"schnorr_verify_nif",         3, schnorr_verify_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_create_nif",          1, pubkey_create_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_tweak_add_nif",       2, pubkey_tweak_add_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xonly_pubkey_tweak_add_nif", 2, xonly_pubkey_tweak_add_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_compress_nif",        1, pubkey_compress_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_decompress_nif",      1, pubkey_decompress_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_combine_nif",         1, pubkey_combine_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ecdsa_sign_nif",             2, ecdsa_sign_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"schnorr_sign_nif",           3, schnorr_sign_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"seckey_tweak_add_nif",       2, seckey_tweak_add_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ellswift_create_nif",        2, ellswift_create_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ellswift_xdh_nif",           4, ellswift_xdh_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(beamchain_crypto, nif_funcs, load, NULL, NULL, unload)
