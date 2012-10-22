-module(poly1305aes).
-author('b@b3k.us').

-export([init/0,
		 make_key/0,
         make_nonce/0,
         clamp/1,
         authenticate/3,
         verify/4]).

-on_load(init/0).

init() ->
    case code:priv_dir(poly1305aes) of
        {error, bad_name} ->
            SoName = filename:join("../priv", "poly1305aes_nifs");
        Dir ->
            SoName = filename:join(Dir, "poly1305aes_nifs")
    end,
    case erlang:load_nif(SoName, 0) of
        ok -> ok;
        {error, {load, _}} -> ok;
        {error, {reload, _}} -> ok;
        {error, {upgrade, _}} -> ok;
        Error -> Error
    end.

-spec make_key() -> binary().
make_key() ->
	crypto:strong_rand_bytes(32).

-spec make_nonce() -> binary().
make_nonce() ->
	crypto:strong_rand_bytes(16).

-spec clamp(binary()) -> {ok, binary()} | {error, atom()}.
clamp(_Kr) ->
	"NIF library not loaded".

-spec authenticate(binary(), binary(), binary()) -> {ok, binary()} | {error, atom()}.
authenticate(_Kr, _N, _M) ->
	"NIF library not loaded".

-spec verify(binary(), binary(), binary(), binary()) -> boolean().
verify(_A, _Kr, _N, _M) ->
	"NIF library not loaded".
