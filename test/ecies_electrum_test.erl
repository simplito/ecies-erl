-module(ecies_electrum_test).

-include_lib("eunit/include/eunit.hrl").

-define(MESSAGE, <<"topsecret">>).

electrum_basic_test() ->
  code:ensure_loaded(libsecp256k1), % ignore result
  case ecies_electrum:is_supported() of
    true ->
      Params = ecies_electrum:default_params(),
      {Pub, Priv} = ecies:generate_key(Params),
      MessageBase64 = ecies:public_encrypt(Pub, ?MESSAGE, Params),
      ?assertEqual(?MESSAGE, ecies:private_decrypt(Priv, MessageBase64, Params));
    false ->
      ?debugMsg("ecies_electrum not supported")
  end.

electrum_case_1_test() ->
  code:ensure_loaded(libsecp256k1), % ignore result
  case ecies_electrum:is_supported() of
    true ->
      Params = ecies_electrum:default_params(),
      PrivateKey    = binary:decode_hex(<<"ee3231b5deea48b619814d72a6e1aa04a9f521df281afad5ada89f5393941b1c">>),
      MessageBase64 = <<"QklFMQJdmY+9Ys1WjqANreLwXaau62N01r9lebJ9Rp7Az+XRMdNAVgg3J8EEVhni5gn2v+WOD59uDMDp0zY/xPT3IElReQo6XUCSMmgRgRtYl+TUEw==">>,
      ExpectedPlainText = <<"hello world">>,
      ?assertEqual(ExpectedPlainText, ecies:private_decrypt(PrivateKey, MessageBase64, Params));
    false ->
      ?debugMsg("ecies_electrum not supported")
  end.
