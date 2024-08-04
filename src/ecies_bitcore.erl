%% @doc
%% This module provides specific params defaults and overrides compatible with Bitcore ECIES implementation.
-module(ecies_bitcore).

-export([default_params/0, params/1]).

%% @doc Default params compatible with bitcore ECIES implementation.
%%
%% Using `secp256k1' elliptic curve, HMAC SHA-256 with 256 bits output authentication tag using
%% AES-128 256 encryption and embedded IV in cipher data.
%% Additionally it provides callbacks for bitcore specific keys and IV derivation functions.
-spec default_params() -> ecies:ecies_params().
default_params() ->
  #{
    curve => secp256k1,
    mac => {hmac, sha256, 256},
    kdf => fun kdf/3,
    iv  => fun iv/1,
    embedded_iv => true
  }.

%% @doc Utility function for overriding default bitcore compatible params
%% @equiv maps:merge(default_params(), Params)
-spec params(Params :: map()) -> ecies:ecies_params().
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
