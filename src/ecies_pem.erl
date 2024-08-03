%% @doc
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
  
  supports/1
]).


encode_public(PublicKey) ->
  encode_public(PublicKey, ecies:default_params()).

encode_public(PublicKey, #{ curve := NamedCurve }) ->
  NamedCurveOid = pubkey_cert_records:namedCurves(NamedCurve),
  AlgorithmIdentifier = {#'ECPoint'{point = PublicKey}, {namedCurve, NamedCurveOid}},
  public_key:pem_encode([public_key:pem_entry_encode('SubjectPublicKeyInfo', AlgorithmIdentifier)]).

decode_public(Pem) ->
  decode_public(Pem, ecies:default_params()).

decode_public(Pem, #{} = Params) ->
  case public_key:pem_decode(Pem) of
    [{'SubjectPublicKeyInfo', AlgorithmIdentifierDER, not_encrypted}] ->
      case public_key:der_decode('SubjectPublicKeyInfo', AlgorithmIdentifierDER) of
        #'SubjectPublicKeyInfo'{subjectPublicKey = PublicKey} ->
          case maps:get(compress_pubkey, Params, true) of
            true  -> ecies_pubkey:compress(PublicKey, Params);
            false -> ecies_pubkey:decompress(PublicKey, Params)
         end;
        _ -> error
      end;
    _ -> error
  end.

-spec encode_private(ecies:private_key()) -> binary().
encode_private(PrivateKey) ->
  encode_private(PrivateKey, ecies:default_params()).

-spec encode_private(ecies:private_key(), #{ curve := ecies:named_curve(), _ => _}) -> binary().
encode_private(PrivateKey, #{ curve := NamedCurve }) ->
  NamedCurveOid = pubkey_cert_records:namedCurves(NamedCurve),
  AlgorithmIdentifier = #'ECPrivateKey'{privateKey = PrivateKey, parameters = {namedCurve, NamedCurveOid}, version=1},
  public_key:pem_encode([public_key:pem_entry_encode('PrivateKeyInfo', AlgorithmIdentifier)]).

-spec decode_private(Pem :: binary()) -> ecies:private_key() | error.
decode_private(Pem) ->
  decode_private(Pem, ecies:default_params()).

-spec decode_private
        (Pem :: binary(), #{ return_curve := true, verify_curve => boolean(), _ => _}) -> {ecies:named_curve(), ecies:private_key()} | error;
        (Pem :: binary(), #{ verify_curve => boolean(), _ => _ }) -> ecies:private_key() | error.
decode_private(Pem, #{} = Params) ->
  try
    [{'PrivateKeyInfo', AlgorithmIdentifierDER, not_encrypted}] = public_key:pem_decode(Pem),
    #'ECPrivateKey'{privateKey = PrivateKey, parameters = {namedCurve, NamedCurveOid}} = public_key:der_decode('PrivateKeyInfo', AlgorithmIdentifierDER),
    postprocess_decode_result(PrivateKey, NamedCurveOid, Params)
  catch _:_ ->
    error
  end.

-spec encode_keypair(ecies:keypair()) -> binary().
encode_keypair(KeyPair) ->
  encode_keypair(KeyPair, ecies:default_params()).

-spec encode_keypair(ecies:keypair(), #{ curve := ecies:named_curve(), _ => _}) -> binary().
encode_keypair({PublicKey, PrivateKey}, #{ curve := NamedCurve }) ->
  NamedCurveOid = pubkey_cert_records:namedCurves(NamedCurve),
  AlgorithmIdentifier = #'ECPrivateKey'{privateKey = PrivateKey, publicKey = PublicKey, parameters = {namedCurve, NamedCurveOid}, version=1},
  public_key:pem_encode([public_key:pem_entry_encode('PrivateKeyInfo', AlgorithmIdentifier)]).

-spec decode_keypair(Pem :: binary()) -> ecies:keypair() | error.
decode_keypair(Pem) ->
  decode_keypair(Pem, ecies:default_params()).

-spec decode_keypair
  (Pem :: binary(), #{ return_curve := true, verify_curve => boolean(), _ => _}) -> {ecies:named_curve(), ecies:keypair()} | error;
  (Pem :: binary(), #{ verify_curve => boolean(), _ => _ }) -> ecies:keypair() | error.
decode_keypair(Pem, #{} = Params) ->
  try
    [{'PrivateKeyInfo', AlgorithmIdentifierDER, not_encrypted}] = public_key:pem_decode(Pem),
    #'ECPrivateKey'{privateKey = PrivateKey, publicKey = PublicKey0, parameters = {namedCurve, NamedCurveOid}} = public_key:der_decode('PrivateKeyInfo', AlgorithmIdentifierDER),
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

% see `pubkey_cert_records:namedCurves/1`
supports(curves) ->
  [
    sect571r1, sect571k1, sect409r1, sect409k1, secp521r1, secp384r1, secp224r1, secp224k1, secp192k1, secp160r2,
    secp128r2, secp128r1, sect233r1, sect233k1, sect193r2, sect193r1, sect131r2, sect131r1, sect283r1, sect283k1,
    sect163r2, secp256k1, secp160k1, secp160r1, secp112r2, secp112r1, sect113r2, sect113r1, sect239k1, sect163r1,
    sect163k1, secp256r1, secp192r1, x25519, x448, brainpoolP160r1, brainpoolP160t1, brainpoolP192r1, brainpoolP192t1,
    brainpoolP224r1, brainpoolP224t1, brainpoolP256r1, brainpoolP256t1, brainpoolP320r1, brainpoolP320t1,
    brainpoolP384r1, brainpoolP384t1, brainpoolP512r1, brainpoolP512t1
  ];
supports(NamedCurve) ->
  lists:member(NamedCurve, supports(curves)).

% priv
normalize_name(ed25519) -> x25519;
normalize_name(ed448) -> x448;
normalize_name(Curve) -> Curve.

normalize_pubkey(PublicKey, Params) ->
  case maps:get(compress_pubkey, Params, true) of
    true  -> ecies_pubkey:compress(PublicKey, Params);
    false -> ecies_pubkey:decompress(PublicKey, Params)
  end.