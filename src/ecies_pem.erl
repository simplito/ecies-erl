%% @doc
%% This module contains functions for encoding and decoding public and private keys, as well as pair of these keys,
%% in PEM format.
%%
-module(ecies_pem).

-include_lib("public_key/include/public_key.hrl").

-export([
  encode_public/1,
  decode_public/1,
  encode_private/1,
  decode_private/1,
  encode_keypair/1,
  decode_keypair/1,
  
  encode_public/2,
  decode_public/2,
  encode_private/2,
  decode_private/2,
  encode_keypair/2,
  decode_keypair/2,

  supports/0,
  supports/1
]).

%% @doc Encodes the given `PublicKey' into PEM "PUBLIC KEY" format.
%% @equiv encode_public(PublicKey, ecies:default_params())
-spec encode_public(PublicKey :: ecies:public_key()) -> binary().
encode_public(PublicKey) ->
  encode_public(PublicKey, ecies:default_params()).

%% @doc Encodes the given `PublicKey' into PEM "PUBLIC KEY" format.
-spec encode_public(ecies:public_key(), ecies:ecies_params()) -> binary().
encode_public(PublicKey, #{ curve := NamedCurve }) ->
  NamedCurveOid = pubkey_cert_records:namedCurves(NamedCurve),
  Entity = {#'ECPoint'{point = PublicKey}, {namedCurve, NamedCurveOid}},
  public_key:pem_encode([public_key:pem_entry_encode('SubjectPublicKeyInfo', Entity)]).

%% @doc Decodes the given `Pem' binary representation a PEM formatted "PUBLIC KEY" or "EC PRIVATE KEY"
%% into a `PublicKey'.
%% @equiv decode_public(PemEncodedPublicKey, ecies:default_params())
-spec decode_public(Pem :: binary()) -> ecies:public_key().
decode_public(Pem) ->
  decode_public(Pem, ecies:default_params()).

%% @doc Decodes the given `Pem' binary representation a PEM formatted "PUBLIC KEY" or "EC PRIVATE KEY"
%% into a `PublicKey'.
-spec decode_public(binary(), ecies:ecies_params()) -> ecies:public_key().
decode_public(Pem, #{} = Params) ->
  try
    case lists:keyfind('SubjectPublicKeyInfo', 1, public_key:pem_decode(Pem)) of
      false ->
        PemEntry = lists:keyfind('ECPrivateKey', 1, public_key:pem_decode(Pem)),
        #'ECPrivateKey'{
          publicKey = PublicKey0,
          parameters = {namedCurve, NamedCurveOid}} = public_key:pem_entry_decode(PemEntry),
        PublicKey0 == asn1_NOVALUE andalso throw(error);
      PemEntry ->
        {#'ECPoint'{point = PublicKey0}, {namedCurve, NamedCurveOid}} = public_key:pem_entry_decode(PemEntry)
    end,
    PublicKey = normalize_pubkey(PublicKey0, Params),
    postprocess_decode_result(PublicKey, NamedCurveOid, Params)
  catch _:_ -> error
  end.

%% @doc Encodes the given `PrivateKey' into PEM "EC PRIVATE KEY" format.
%% @equiv encode_private(PrivateKey, ecies:default_params())
-spec encode_private(PrivateKey :: ecies:private_key()) -> binary().
encode_private(PrivateKey) ->
  encode_private(PrivateKey, ecies:default_params()).

%% @doc Encodes the given `PrivateKey' into PEM "EC PRIVATE KEY" format.
-spec encode_private(PrivateKey :: ecies:private_key(), #{ curve := ecies:named_curve(), _ => _}) -> binary().
encode_private(PrivateKey, #{ curve := NamedCurve }) ->
  NamedCurveOid = pubkey_cert_records:namedCurves(NamedCurve),
  ECPrivateKey = #'ECPrivateKey'{
    privateKey = PrivateKey,
    parameters = {namedCurve, NamedCurveOid},
    version=1},
  public_key:pem_encode([public_key:pem_entry_encode('ECPrivateKey', ECPrivateKey)]).

%% @doc Decodes the given `Pem' binary representation a PEM formatted "EC PRIVATE KEY" into a `PrivateKey'.
%% @equiv decode_private(Pem, ecies:default_params())
-spec decode_private(Pem :: binary()) -> ecies:private_key() | error.
decode_private(Pem) ->
  decode_private(Pem, ecies:default_params()).

%% @doc Decodes the given `Pem' binary representation a PEM formatted "EC PRIVATE KEY" into a `PrivateKey'.
-spec decode_private
        (Pem :: binary(), #{ return_curve := true, verify_curve => boolean(), _ => _}) -> {ecies:named_curve(), ecies:private_key()} | error;
        (Pem :: binary(), #{ verify_curve => boolean(), _ => _ }) -> ecies:private_key() | error.
decode_private(Pem, #{} = Params) ->
  try
    PemEntry = lists:keyfind('ECPrivateKey', 1, public_key:pem_decode(Pem)),
    #'ECPrivateKey'{
      privateKey = PrivateKey,
      parameters = {namedCurve, NamedCurveOid}} = public_key:pem_entry_decode(PemEntry),
    postprocess_decode_result(PrivateKey, NamedCurveOid, Params)
  catch _:_ ->
    error
  end.

%% @doc Encodes the given `KeyPair' into PEM "EC PRIVATE KEY" format (public key included).
%% @equiv encode_keypair(KeyPair, ecies:default_params())
-spec encode_keypair(KeyPair :: ecies:keypair()) -> binary().
encode_keypair(KeyPair) ->
  encode_keypair(KeyPair, ecies:default_params()).

%% @doc Encodes the given `KeyPair' into PEM "EC PRIVATE KEY" format (public key included).
-spec encode_keypair(ecies:keypair(), #{ curve := ecies:named_curve(), _ => _}) -> binary().
encode_keypair({PublicKey, PrivateKey}, #{ curve := NamedCurve }) ->
  NamedCurveOid = pubkey_cert_records:namedCurves(NamedCurve),
  ECPrivateKey = #'ECPrivateKey'{privateKey = PrivateKey, publicKey = PublicKey, parameters = {namedCurve, NamedCurveOid}, version=1},
  public_key:pem_encode([public_key:pem_entry_encode('ECPrivateKey', ECPrivateKey)]).

%% @doc Decodes the given `Pem' binary representation a PEM formatted "EC PRIVATE KEY" into a key pair
%% {`PublicKey', `PrivateKey'}.
%% If the public key is not included in the given `Pem`, it recovers the public key from the private one
%% using `ecies_pubkey:from_private/2'. This is only possible for curves returned by `ecies_pubkey:supports_from_private/0'.
%% @equiv decode_keypair(Pem, ecies:default_params())
-spec decode_keypair(Pem :: binary()) -> ecies:keypair() | error.
decode_keypair(Pem) ->
  decode_keypair(Pem, ecies:default_params()).

%% @doc Decodes the given `Pem' binary representation a PEM formatted "EC PRIVATE KEY" into a key pair
%% {`PublicKey', `PrivateKey'}.
%% If the public key is not included in the given `Pem`, it recovers the public key from the private one
%% using `ecies_pubkey:from_private/2'. This is only possible for curves returned by `ecies_pubkey:supports_from_private/0'.
%% @equiv decode_keypair(Pem, ecies:default_params())
-spec decode_keypair
  (Pem :: binary(), #{ return_curve := true, verify_curve => boolean(), _ => _}) -> {ecies:named_curve(), ecies:keypair()} | error;
  (Pem :: binary(), #{ verify_curve => boolean(), _ => _ }) -> ecies:keypair() | error.
decode_keypair(Pem, #{} = Params) ->
  try
    PemEntry = lists:keyfind('ECPrivateKey', 1, public_key:pem_decode(Pem)),
    #'ECPrivateKey'{
      privateKey = PrivateKey,
      publicKey = PublicKey0,
      parameters = {namedCurve, NamedCurveOid}} = public_key:pem_entry_decode(PemEntry),
    PublicKey =
      case PublicKey0 of
        'asn1_NOVALUE' -> ecies_pubkey:from_private(PrivateKey, Params);
        _ when is_binary(PublicKey0) -> normalize_pubkey(PublicKey0, Params)
      end,
    KeyPair = {PublicKey, PrivateKey},
    postprocess_decode_result(KeyPair, NamedCurveOid, Params)
  catch _:_ ->
    error
  end.

% priv
postprocess_decode_result(Result, NamedCurveOid, Params) ->
  ReturnCurve = maps:get(return_curve, Params, false),
  VerifyCurve = maps:get(verify_curve, Params, not ReturnCurve),
  NamedCurve = normalize_name(pubkey_cert_records:namedCurves(NamedCurveOid)),
  case VerifyCurve of
    true ->
      ExpectedCurve = maps:get(curve, Params),
      case {NamedCurve, ExpectedCurve} of
        {Same, Same} -> ok;
        _ -> throw(error)
      end;
    false ->
      ok
  end,
  case ReturnCurve of
    true -> {NamedCurve, Result};
    false -> Result
  end.

%% @doc Returns a list of named curves that are supported by the `ecies_pem' module.
%% @see pubkey_cert_records:namedCurves/1
-spec supports() -> list(ecies:named_curve()).
supports() ->
  [
    sect571r1, sect571k1, sect409r1, sect409k1, secp521r1, secp384r1, secp224r1, secp224k1, secp192k1, secp160r2,
    secp128r2, secp128r1, sect233r1, sect233k1, sect193r2, sect193r1, sect131r2, sect131r1, sect283r1, sect283k1,
    sect163r2, secp256k1, secp160k1, secp160r1, secp112r2, secp112r1, sect113r2, sect113r1, sect239k1, sect163r1,
    sect163k1, secp256r1, secp192r1, x25519, x448, brainpoolP160r1, brainpoolP160t1, brainpoolP192r1, brainpoolP192t1,
    brainpoolP224r1, brainpoolP224t1, brainpoolP256r1, brainpoolP256t1, brainpoolP320r1, brainpoolP320t1,
    brainpoolP384r1, brainpoolP384t1, brainpoolP512r1, brainpoolP512t1
  ].

%% @doc Checks if the given `NamedCurve' is supported by the `ecies_pem' module.
-spec supports(NamedCurve :: ecies:named_curve()) -> boolean().
supports(NamedCurve) ->
  lists:member(NamedCurve, supports()).

% priv
normalize_name(ed25519) -> x25519;
normalize_name(ed448) -> x448;
normalize_name(Curve) -> Curve.

normalize_pubkey(PublicKey, Params) ->
  case maps:get(compress_pubkey, Params, true) of
    true  -> ecies_pubkey:compress(PublicKey, Params);
    false -> ecies_pubkey:decompress(PublicKey, Params)
  end.
