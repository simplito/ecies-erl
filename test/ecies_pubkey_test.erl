-module(ecies_pubkey_test).

-include_lib("eunit/include/eunit.hrl").

from_private_curves_test_() ->
  SupportedCurves = ecies_pubkey:supports_from_private(curves),
  [{
    atom_to_list(Curve) ++ " from_private",
    fun() ->
      Params = #{ curve => Curve },
      {Pub, Priv} = ecies:generate_key(Params),
      ?assertEqual(Pub, ecies_pubkey:from_private(Priv, Params))
    end
  } || Curve <- SupportedCurves].
