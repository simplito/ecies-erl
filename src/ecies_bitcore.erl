-module(ecies_bitcore).

-export([default_params/0, params/1]).

default_params() ->
  #{
    curve => secp256k1,
    mac => {hmac, sha256, 256},
    kdf => fun kdf/3,
    iv  => fun iv/1,
    embedded_iv => true
  }.

params(Params) ->
  maps:merge(default_params(), Params).

% bitcore specific overrides
kdf(SharedKey, _Info, 64) ->
  crypto:hash(sha512, SharedKey).

iv(State) ->
  % bitcore uses deterministic IV generation but actually embeds it in final payload,
  % so could be standard one as well
  #{ key := {_PublicKey, PrivateKey}, plain_text := PlainText, iv_length := IVLen } = State,
  <<IV:IVLen/bytes, _/binary>> = crypto:mac(hmac, sha256, PrivateKey, PlainText),
  {ok, State#{ iv => IV }}.
