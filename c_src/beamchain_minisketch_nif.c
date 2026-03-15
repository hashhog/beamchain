/**
 * beamchain_minisketch_nif.c - Minisketch NIF bindings for Erlang
 *
 * Wraps the libminisketch library for BIP330 Erlay set reconciliation.
 * Uses 32-bit elements for short txid representation.
 */

#include <string.h>
#include <erl_nif.h>

/* Check if minisketch is available */
#ifdef HAVE_MINISKETCH
#include <minisketch.h>
#define MINISKETCH_AVAILABLE 1
#else
#define MINISKETCH_AVAILABLE 0
#endif

/* Resource type for minisketch handles */
static ErlNifResourceType *minisketch_resource;

/* ------------------------------------------------------------------ */
/* NIF lifecycle                                                       */
/* ------------------------------------------------------------------ */

static void minisketch_dtor(ErlNifEnv *env, void *obj)
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr = (minisketch **)obj;
    if (*sketch_ptr) {
        minisketch_destroy(*sketch_ptr);
        *sketch_ptr = NULL;
    }
#else
    (void)env;
    (void)obj;
#endif
}

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    (void)priv_data;
    (void)load_info;

    minisketch_resource = enif_open_resource_type(
        env, NULL, "minisketch",
        minisketch_dtor, ERL_NIF_RT_CREATE, NULL);

    if (!minisketch_resource) return -1;
    return 0;
}

static void unload(ErlNifEnv *env, void *priv_data)
{
    (void)env;
    (void)priv_data;
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

static ERL_NIF_TERM make_ok_ref(ErlNifEnv *env, ERL_NIF_TERM ref)
{
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), ref);
}

/* ------------------------------------------------------------------ */
/* create_nif(Bits, Capacity) -> {ok, Ref} | {error, reason}           */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM create_nif(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    unsigned int bits, capacity;

    if (!enif_get_uint(env, argv[0], &bits) ||
        !enif_get_uint(env, argv[1], &capacity))
        return enif_make_badarg(env);

    if (!minisketch_bits_supported(bits))
        return make_error(env, "unsupported_bits");

    minisketch *sketch = minisketch_create(bits, 0, capacity);
    if (!sketch)
        return make_error(env, "create_failed");

    minisketch **sketch_ptr = enif_alloc_resource(minisketch_resource,
                                                   sizeof(minisketch *));
    *sketch_ptr = sketch;

    ERL_NIF_TERM ref = enif_make_resource(env, sketch_ptr);
    enif_release_resource(sketch_ptr);

    return make_ok_ref(env, ref);
#else
    (void)argc;
    (void)argv;
    return make_error(env, "minisketch_not_available");
#endif
}

/* ------------------------------------------------------------------ */
/* clone_nif(Ref) -> {ok, NewRef} | {error, reason}                    */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM clone_nif(ErlNifEnv *env, int argc,
                               const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr;

    if (!enif_get_resource(env, argv[0], minisketch_resource, (void **)&sketch_ptr))
        return enif_make_badarg(env);

    if (!*sketch_ptr)
        return make_error(env, "destroyed");

    minisketch *clone = minisketch_clone(*sketch_ptr);
    if (!clone)
        return make_error(env, "clone_failed");

    minisketch **clone_ptr = enif_alloc_resource(minisketch_resource,
                                                  sizeof(minisketch *));
    *clone_ptr = clone;

    ERL_NIF_TERM ref = enif_make_resource(env, clone_ptr);
    enif_release_resource(clone_ptr);

    return make_ok_ref(env, ref);
#else
    (void)argc;
    (void)argv;
    return make_error(env, "minisketch_not_available");
#endif
}

/* ------------------------------------------------------------------ */
/* add_nif(Ref, Element) -> ok                                         */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM add_nif(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr;
    ErlNifUInt64 element;

    if (!enif_get_resource(env, argv[0], minisketch_resource, (void **)&sketch_ptr))
        return enif_make_badarg(env);

    if (!enif_get_uint64(env, argv[1], &element))
        return enif_make_badarg(env);

    if (!*sketch_ptr)
        return make_error(env, "destroyed");

    minisketch_add_uint64(*sketch_ptr, element);
    return enif_make_atom(env, "ok");
#else
    (void)argc;
    (void)argv;
    return enif_make_atom(env, "ok");
#endif
}

/* ------------------------------------------------------------------ */
/* merge_nif(Ref, OtherRef) -> ok | {error, reason}                    */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM merge_nif(ErlNifEnv *env, int argc,
                               const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr, **other_ptr;

    if (!enif_get_resource(env, argv[0], minisketch_resource, (void **)&sketch_ptr) ||
        !enif_get_resource(env, argv[1], minisketch_resource, (void **)&other_ptr))
        return enif_make_badarg(env);

    if (!*sketch_ptr || !*other_ptr)
        return make_error(env, "destroyed");

    size_t result = minisketch_merge(*sketch_ptr, *other_ptr);
    if (result == 0)
        return make_error(env, "merge_failed");

    return enif_make_atom(env, "ok");
#else
    (void)argc;
    (void)argv;
    return make_error(env, "minisketch_not_available");
#endif
}

/* ------------------------------------------------------------------ */
/* serialized_size_nif(Ref) -> Size                                    */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM serialized_size_nif(ErlNifEnv *env, int argc,
                                         const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr;

    if (!enif_get_resource(env, argv[0], minisketch_resource, (void **)&sketch_ptr))
        return enif_make_badarg(env);

    if (!*sketch_ptr)
        return enif_make_uint(env, 0);

    size_t size = minisketch_serialized_size(*sketch_ptr);
    return enif_make_uint64(env, size);
#else
    (void)argc;
    (void)argv;
    return enif_make_uint(env, 0);
#endif
}

/* ------------------------------------------------------------------ */
/* serialize_nif(Ref) -> {ok, Binary} | {error, reason}                */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM serialize_nif(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr;

    if (!enif_get_resource(env, argv[0], minisketch_resource, (void **)&sketch_ptr))
        return enif_make_badarg(env);

    if (!*sketch_ptr)
        return make_error(env, "destroyed");

    size_t size = minisketch_serialized_size(*sketch_ptr);
    ERL_NIF_TERM bin;
    unsigned char *buf = enif_make_new_binary(env, size, &bin);

    minisketch_serialize(*sketch_ptr, buf);

    return enif_make_tuple2(env, enif_make_atom(env, "ok"), bin);
#else
    (void)argc;
    (void)argv;
    return make_error(env, "minisketch_not_available");
#endif
}

/* ------------------------------------------------------------------ */
/* deserialize_nif(Ref, Binary) -> ok | {error, reason}                */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM deserialize_nif(ErlNifEnv *env, int argc,
                                     const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr;
    ErlNifBinary bin;

    if (!enif_get_resource(env, argv[0], minisketch_resource, (void **)&sketch_ptr))
        return enif_make_badarg(env);

    if (!enif_inspect_binary(env, argv[1], &bin))
        return enif_make_badarg(env);

    if (!*sketch_ptr)
        return make_error(env, "destroyed");

    size_t expected_size = minisketch_serialized_size(*sketch_ptr);
    if (bin.size != expected_size)
        return make_error(env, "size_mismatch");

    minisketch_deserialize(*sketch_ptr, bin.data);
    return enif_make_atom(env, "ok");
#else
    (void)argc;
    (void)argv;
    return make_error(env, "minisketch_not_available");
#endif
}

/* ------------------------------------------------------------------ */
/* decode_nif(Ref, MaxElements) -> {ok, [Elements]} | {error, reason}  */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM decode_nif(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr;
    unsigned int max_elements;

    if (!enif_get_resource(env, argv[0], minisketch_resource, (void **)&sketch_ptr))
        return enif_make_badarg(env);

    if (!enif_get_uint(env, argv[1], &max_elements))
        return enif_make_badarg(env);

    if (!*sketch_ptr)
        return make_error(env, "destroyed");

    uint64_t *output = enif_alloc(sizeof(uint64_t) * max_elements);
    if (!output)
        return make_error(env, "alloc_failed");

    ssize_t num_decoded = minisketch_decode(*sketch_ptr, max_elements, output);

    if (num_decoded < 0) {
        enif_free(output);
        return make_error(env, "decode_failed");
    }

    /* Build list of decoded elements */
    ERL_NIF_TERM list = enif_make_list(env, 0);
    for (ssize_t i = num_decoded - 1; i >= 0; i--) {
        list = enif_make_list_cell(env, enif_make_uint64(env, output[i]), list);
    }

    enif_free(output);
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), list);
#else
    (void)argc;
    (void)argv;
    return make_error(env, "minisketch_not_available");
#endif
}

/* ------------------------------------------------------------------ */
/* bits_nif(Ref) -> Bits                                               */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM bits_nif(ErlNifEnv *env, int argc,
                              const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr;

    if (!enif_get_resource(env, argv[0], minisketch_resource, (void **)&sketch_ptr))
        return enif_make_badarg(env);

    if (!*sketch_ptr)
        return enif_make_uint(env, 0);

    return enif_make_uint(env, minisketch_bits(*sketch_ptr));
#else
    (void)argc;
    (void)argv;
    return enif_make_uint(env, 32);
#endif
}

/* ------------------------------------------------------------------ */
/* capacity_nif(Ref) -> Capacity                                       */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM capacity_nif(ErlNifEnv *env, int argc,
                                  const ERL_NIF_TERM argv[])
{
#if MINISKETCH_AVAILABLE
    minisketch **sketch_ptr;

    if (!enif_get_resource(env, argv[0], minisketch_resource, (void **)&sketch_ptr))
        return enif_make_badarg(env);

    if (!*sketch_ptr)
        return enif_make_uint(env, 0);

    return enif_make_uint64(env, minisketch_capacity(*sketch_ptr));
#else
    (void)argc;
    (void)argv;
    return enif_make_uint(env, 0);
#endif
}

/* ------------------------------------------------------------------ */
/* NIF function table                                                  */
/* ------------------------------------------------------------------ */

static ErlNifFunc nif_funcs[] = {
    {"create_nif", 2, create_nif, 0},
    {"clone_nif", 1, clone_nif, 0},
    {"add_nif", 2, add_nif, 0},
    {"merge_nif", 2, merge_nif, 0},
    {"serialized_size_nif", 1, serialized_size_nif, 0},
    {"serialize_nif", 1, serialize_nif, 0},
    {"deserialize_nif", 2, deserialize_nif, 0},
    {"decode_nif", 2, decode_nif, 0},
    {"bits_nif", 1, bits_nif, 0},
    {"capacity_nif", 1, capacity_nif, 0}
};

ERL_NIF_INIT(beamchain_minisketch, nif_funcs, load, NULL, NULL, unload)
