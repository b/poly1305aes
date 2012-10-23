-module(poly1305aes_tests).

-include_lib("eunit/include/eunit.hrl").

parse_lines(Lines) ->
	lists:map(
		fun(L) ->
			Line = case string:tokens(L, ",") of
				[Kr, N, M, Len, A] -> [Kr, N, M, Len, A];
				[Kr, N, Len, A] -> [Kr, N, "", Len, A]
			end,
			lists:map(fun hex:hexstr_to_bin/1, Line)
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

% add tests for things that should fail
