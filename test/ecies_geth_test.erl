-module(ecies_geth_test).

-include_lib("eunit/include/eunit.hrl").

-define(MESSAGE, <<"topsecret">>).

basic_test() ->
  Params = ecies_geth:params_from_curve(secp256r1),
  {Pub, Priv} = ecies:generate_key(Params),
  Data = ecies:public_encrypt(Pub, ?MESSAGE, Params),
  ?assertEqual(?MESSAGE, ecies:private_decrypt(Priv, Data, Params)).
