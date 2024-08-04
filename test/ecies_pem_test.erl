-module(ecies_pem_test).

-include_lib("eunit/include/eunit.hrl").

supported_curves_basic_test_() ->
  SupportedCurves = ecies_pem:supports(),
  [{
      atom_to_list(Curve) ++ " pem",
      fun() ->
        Params = #{ curve => Curve },
        {Pub, Priv} = KeyPair = ecies:generate_key(Params),
        ?assertEqual(Pub, ecies_pem:decode_public(ecies_pem:encode_public(Pub, Params), Params)),
        ?assertEqual(Priv, ecies_pem:decode_private(ecies_pem:encode_private(Priv, Params), Params)),
        ?assertEqual(KeyPair, ecies_pem:decode_keypair(ecies_pem:encode_keypair(KeyPair, Params),Params)),
        % For now decoding keypair from private key of edward curves is not implemented
        case ecies_pubkey:supports_from_private(Curve) of
          true -> ?assertEqual(KeyPair, ecies_pem:decode_keypair(ecies_pem:encode_private(Priv, Params), Params));
          false -> ?assertEqual(error, ecies_pem:decode_keypair(ecies_pem:encode_private(Priv, Params), Params))
        end
      end
  } || Curve <- SupportedCurves].

supported_curves_keypair_from_private_test_() ->
  SupportedCurves = ordsets:intersection(ordsets:from_list(ecies_pem:supports()), ordsets:from_list(ecies_pubkey:supports_from_private())),
  [{
      atom_to_list(Curve) ++ " keypair from private pem",
    fun() ->
      Params = #{ curve => Curve },
      {_Pub, Priv} = KeyPair = ecies:generate_key(Params),
      ?assertEqual(KeyPair, ecies_pem:decode_keypair(ecies_pem:encode_private(Priv, Params), Params))
    end
  } || Curve <- SupportedCurves].

unsupported_curves_keypair_from_private_test_() ->
  UnsupportedCurves = ordsets:subtract(ordsets:from_list(ecies_pem:supports()), ordsets:from_list(ecies_pubkey:supports_from_private())),
  [{
      atom_to_list(Curve) ++ " unsupported keypair from private pem",
    fun() ->
      Params = #{ curve => Curve },
      {_Pub, Priv} = ecies:generate_key(Params),
      ?assertEqual(error, ecies_pem:decode_keypair(ecies_pem:encode_private(Priv, Params), Params))
    end
  } || Curve <- UnsupportedCurves].
 