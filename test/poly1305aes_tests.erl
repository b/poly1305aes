-module(poly1305aes_tests).

-include_lib("eunit/include/eunit.hrl").

hexstr_to_bin(S) ->
  hexstr_to_bin(S, []).
hexstr_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hexstr_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hexstr_to_bin(T, [V | Acc]);
hexstr_to_bin([X|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", lists:flatten([X,"0"])),
  hexstr_to_bin(T, [V | Acc]).

parse_lines(Lines) ->
	lists:map(
		fun(L) ->
			Line = case string:tokens(L, ",") of
				[Kr, N, M, Len, A] -> [Kr, N, M, Len, A];
				[Kr, N, Len, A] -> [Kr, N, "", Len, A]
			end,
			lists:map(fun hexstr_to_bin/1, Line)
		end,
		Lines).

authenticate([Kr, N, M, _Len, A]) ->
	{ok, Out} = poly1305aes:authenticate(Kr, N, M),
	?assertEqual(Out, A).

verify([Kr, N, M, _Len, A]) ->
	?assert(poly1305aes:verify(A, Kr, N, M)).

test_data(Fun) ->
	{ok, Cwd} = file:get_cwd(),
    Filename = filename:join([Cwd, "..", "test", "data", "test-poly1305aes.full.out.zip"]),
    {ok, ZipHandle} = zip:zip_open(Filename, [memory]),
    {ok, {_, Data}} = zip:zip_get("test-poly1305aes.full.out", ZipHandle),

    lists:foreach(
        fun(L) ->
            Fun(L)
        end, parse_lines(string:tokens(binary_to_list(Data), "\n"))).

authenticate_test_() -> {timeout, 60, fun() -> test_data(fun authenticate/1) end}.
verify_test_() -> {timeout, 60, fun() -> test_data(fun verify/1) end}.
