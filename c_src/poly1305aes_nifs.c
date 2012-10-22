#include "erl_nif.h"
#include "poly1305aes/poly1305aes.h"

#define AN_GIGABYTE 1000000000

// Prototypes
ERL_NIF_TERM poly1305_aes_clamp(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM poly1305_aes_authenticate(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM poly1305_aes_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

// lifecycle
int load(ErlNifEnv* env, void ** priv_data, ERL_NIF_TERM load_info);
int reload(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info);
int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM load_info);
void unload(ErlNifEnv* env, void* priv);

static ErlNifFunc nif_funcs[] =
{
    {"clamp", 1, poly1305_aes_clamp},
    {"authenticate", 3, poly1305_aes_authenticate},
    {"verify", 4, poly1305_aes_verify}
};

ERL_NIF_INIT(poly1305aes, nif_funcs, load, NULL, NULL, NULL);

int load(ErlNifEnv* env, void ** priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

int reload(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
    return 0;
}

int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM load_info)
{
    return 0;
}

void unload(ErlNifEnv* env, void* priv)
{
    return;
}

ERL_NIF_TERM poly1305_aes_clamp(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{       
    ErlNifBinary kr;
    enif_inspect_binary(env, argv[0], &kr);

    if (kr.size != 32)
    {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "invalid_key"));
    }

    poly1305aes_clamp(kr.data);
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_binary(env, &kr));
}

ERL_NIF_TERM poly1305_aes_authenticate(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary out, kr, n, m;
    
    enif_inspect_binary(env, argv[0], &kr);
    if (kr.size != 32)
    {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "invalid_key"));
    }

    enif_inspect_binary(env, argv[1], &n);
    if (n.size != 16)
    {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "invalid_nonce"));
    }

    enif_inspect_binary(env, argv[2], &m);
    if (m.size > AN_GIGABYTE)
    {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "too_much_data"));
    }

    if (!enif_alloc_binary(16, &out))
    {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "authenticator_alloc_failed"));
    }

    poly1305aes_authenticate(out.data, kr.data, n.data, m.data, m.size);
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_binary(env, &out));
}

ERL_NIF_TERM poly1305_aes_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary a, kr, n, m;
    
    enif_inspect_binary(env, argv[0], &a);
    if (a.size != 16)
    {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "invalid_authenticator"));
    }

    enif_inspect_binary(env, argv[1], &kr);
    if (kr.size != 32)
    {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "invalid_key"));
    }

    enif_inspect_binary(env, argv[2], &n);
    if (n.size != 16)
    {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "invalid_nonce"));
    }

    enif_inspect_binary(env, argv[3], &m);
    if (m.size > AN_GIGABYTE)
    {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "too_much_data"));
    }

    if (poly1305aes_verify(a.data, kr.data, n.data, m.data, m.size) == 0)
    {
        return enif_make_atom(env, "false");
    } else {
        return enif_make_atom(env, "true");
    }
}
