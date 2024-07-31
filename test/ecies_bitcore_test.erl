-module(ecies_bitcore_test).

-include_lib("eunit/include/eunit.hrl").

-define(MESSAGE, <<"topsecret">>).

basic_test() ->
  Params = ecies_bitcore:default_params(),
  {Pub, Priv} = ecies:generate_key(Params),
  MessageBase64 = ecies:public_encrypt(Pub, ?MESSAGE, Params),
  ?assertEqual(?MESSAGE, ecies:private_decrypt(Priv, MessageBase64, Params)).

case_1_test() ->
  Params = ecies_bitcore:default_params(),
  PrivateKey = binary:decode_hex(<<"2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d">>),
  Message = binary:decode_hex(<<"0339e504d6492b082da96e11e8f039796b06cd4855c101e2492a6f10f3e056a9e712c732611c6917ab5c57a1926973bc44a1586e94a783f81d05ce72518d9b0a80e2e13c7ff7d1306583f9cc7a48def5b37fbf2d5f294f128472a6e9c78dede5f5">>),
  ExpectedPlainText = <<"attack at dawn">>,
  ?assertEqual(ExpectedPlainText, ecies:private_decrypt(PrivateKey, Message, Params)).
