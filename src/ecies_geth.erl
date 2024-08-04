%% @doc
%% This module provides specific params defaults and overrides compatible with ethereum geth ECIES implementation.
-module(ecies_geth).

-export([
  default_params/0,
  params/1,
  params_from_curve/1
]).

%% @doc Default params compatible with ethereum geth ECIES implementation.
%%
%% Using `secp256k1' elliptic curve with NIST SP 800-56 Concatenation Key Derivation Function, 
%% AES-128 CTR encryption and HMAC-SHA256 with 128 bits output authentication tag.
%% Additionally it provides callback for geth specific key derivation function, and ensures
%% usage of random IV which is embedded in cipher data.
-spec default_params() -> ecies:ecies_params().
default_params() ->
  #{
    curve           => secp256k1,
    compress_pubkey => false,
    cipher          => aes_128_ctr,
    mac             => {hmac, sha256, 128},
    kdf             => {concat_kdf, sha256},
    iv              => random,
    embedded_iv     => true,
    derive_keys     => fun derive_keys/1
  }.

%% @doc Utility function for overriding default geth compatible params
%% @equiv maps:merge(default_params(), Params)
-spec params(Params :: map()) -> ecies:ecies_params().
params(Params) ->
  maps:merge(default_params(), Params).

%% @doc Returns params compatible with ethereum geth ECIES implementation for given elliptic curve.
-spec params_from_curve(secp256k1 | secp256r1 | secp384r1 | secp521r1) -> ecies:ecies_params().
params_from_curve(secp256k1) -> % S256
  default_params();
params_from_curve(secp256r1) -> % P256
  params(#{ curve => secp256r1 });
params_from_curve(secp384r1) -> % P384
  params(#{
    curve  => secp384r1,
    cipher => aes_192_ctr,
    kdf    => {concat_kdf, sha384},
    mac    => {hmac, sha384, 384 }
  });
params_from_curve(secp521r1) -> % P521
  params(#{
    curve  => secp521r1,
    cipher => aes_256_ctr,
    kdf    => {concat_kdf, sha512},
    mac    => {hmac, sha512, 512 }
  }).

% geth specific override
derive_keys(State) ->
  #{shared_key := SharedKey, enc_key_length := EncKeyLen, s1 := Info, kdf := {concat_kdf, Hash}} = State,
  <<EncKey:EncKeyLen/bytes, MacKey0:EncKeyLen/bytes>> = ecies_kdf:concat_kdf(Hash, SharedKey, Info, 2*EncKeyLen),
  MacKey = crypto:hash(sha256, MacKey0),
  {ok, State#{ enc_key => EncKey, mac_key => MacKey }}.