%% @doc This module contains functions for compressing, decompressing public key, deriving public key
%% from the given private one and function for EC point multiplication.
-module(ecies_pubkey).

-export([
  compress/1,
  compress/2,
  decompress/1,
  decompress/2,
  from_private/1,
  from_private/2,
  mul/2,
  mul/3,
  
  supports_from_private/0,
  supports_from_private/1,
  supports_decompress/0,
  supports_decompress/1,

  point_bits/1
]).

%% @doc Returns a list of named curves that are supported by the `from_private/1' and `from_private/2' functions.
-spec supports_from_private() -> list(ecies:named_curve()).
supports_from_private() ->
  [
    % supports both point decompression and from_private
    secp160k1, secp160r1, secp160r2, secp192k1, secp256k1, secp384r1, secp521r1, secp192r1, prime192v1, prime192v2,
    prime192v3, prime239v1, prime239v2, prime239v3, secp256r1, prime256v1, wtls7, wtls9, brainpoolP160r1,
    brainpoolP160t1, brainpoolP192r1, brainpoolP192t1, brainpoolP224r1, brainpoolP224t1, brainpoolP256r1,
    brainpoolP256t1, brainpoolP320r1, brainpoolP320t1, brainpoolP384r1, brainpoolP384t1, brainpoolP512r1,
    brainpoolP512t1, secp112r1, secp112r2, secp128r1, secp128r2, wtls6, wtls8,
    % supports only from_private for now
    secp224r1, secp224k1, wtls12
  ].

%% @doc Checks if the given `NamedCurve' is supported by the `from_private/1' and `from_private/2' functions.
-spec supports_from_private(NamedCurve :: ecies:named_curve()) -> boolean().
supports_from_private(NamedCurve) ->
  lists:member(NamedCurve, supports_from_private()).

%% @doc Returns a list of named curves that are supported by the `decompress/1' and `decompress/2' functions.
-spec supports_decompress() -> list(ecies:named_curve()).
supports_decompress() ->
  [
    % supports both point decompression and from_private
    secp160k1, secp160r1, secp160r2, secp192k1, secp256k1, secp384r1, secp521r1, secp192r1, prime192v1, prime192v2,
    prime192v3, prime239v1, prime239v2, prime239v3, secp256r1, prime256v1, wtls7, wtls9, brainpoolP160r1,
    brainpoolP160t1, brainpoolP192r1, brainpoolP192t1, brainpoolP224r1, brainpoolP224t1, brainpoolP256r1,
    brainpoolP256t1, brainpoolP320r1, brainpoolP320t1, brainpoolP384r1, brainpoolP384t1, brainpoolP512r1,
    brainpoolP512t1, secp112r1, secp112r2, secp128r1, secp128r2, wtls6, wtls8
  ].

%% @doc Checks if the given `NamedCurve' is supported by the `decompress/1' and `decompress/2' functions.
-spec supports_decompress(NamedCurve :: ecies:named_curve()) -> boolean().
supports_decompress(NamedCurve) ->
  lists:member(NamedCurve, supports_decompress()).

%% @doc Compresses the `PublicKey', which is a binary representation of an elliptic curve point.
%% Returns the `PublicKey' unchanged if it is already in compressed form.
%% @equiv compress(PubKey, ecies:default_params())
-spec compress(ecies:public_key()) -> ecies:public_key().
compress(PubKey) ->
  compress(PubKey, ecies:default_params()).

%% @doc Compresses the `PublicKey', which is a binary representation of an elliptic curve point.
%% Returns the `PublicKey' unchanged if it is already in compressed form.
compress(PubKey, #{ curve := NamedCurve }) when NamedCurve == x25519; NamedCurve == x448 -> PubKey;
compress(<<2,_/binary>> = PubKey, _Params) -> PubKey;
compress(<<3,_/binary>> = PubKey, _Params) -> PubKey;
compress(<<4,XY/binary>>, _Params) ->
  try
    L = byte_size(XY) div 2,
    <<X:L/bytes, Y:L/bytes>> = XY,
    <<(2 + binary:last(Y) band 1), X/binary>>
  catch _:_ ->
    error(badarg)
  end;
compress(_PubKey, _Params) ->
  error(badarg).

%% @doc
%% Decompresses the `PublicKey', which is a binary representation of an elliptic curve point.
%%
%% If the `PublicKey' is already in decompressed form, it returns the `PublicKey' unchanged.
%% @equiv decompress(PublicKey, ecies:default_params())
-spec decompress(PublicKey :: ecies:public_key()) -> ecies:public_key().
decompress(PublicKey) ->
  decompress(PublicKey, ecies:default_params()).

%% @doc
%% Decompresses the `PublicKey', which is a binary representation of an elliptic curve point.
%%
%% If the `PublicKey' is already in decompressed form, it returns the `PublicKey' unchanged.
%% This function is only valid for curves returned by the `supports_decompress/0' function.
%% @see supports_decompress/0
%% @see supports_decompress/1
-spec decompress(PublicKey :: ecies:public_key(), ecies:ecies_params()) -> ecies:public_key().
decompress(<<Tag, XY/binary>> = PublicKey, #{ curve := NamedCurve }) when Tag == 2; Tag == 3 ->
  {A, B, P, _N} = curve_details(NamedCurve),
  case P band 3 of
    3 -> ok;
    _ -> error(badarg, [PublicKey, #{ curve => NamedCurve }])
  end,
  Pbits = point_bits(NamedCurve),
  <<X:Pbits>> = XY,
  Y2 = mod(X*X*X + A*X + B, P),
  BinY0 = crypto:mod_pow(Y2, (P + 1) div 4, P),
  Y0 = crypto:bytes_to_integer(BinY0),
  Y =
    case (Y0 band 1) == (Tag band 1) of
      true  -> Y0;
      false -> P - Y0
  end,
  <<4, X:Pbits, Y:Pbits>>;
decompress(<<4, XY/binary>> = PubKey, #{ curve := NamedCurve }) ->
  Pbits = point_bits(NamedCurve),
  case XY of
    <<_:Pbits, _:Pbits>> -> ok;
    _ -> error(badarg)
  end,
  PubKey.

%% @doc Calculates a public key from the given `PrivateKey'.
%% @equiv from_private(PrivateKey, ecies:default_params())
-spec from_private(PrivateKey :: ecies:private_key()) -> ecies:public_key().
from_private(PrivKey) ->
  from_private(PrivKey, ecies:default_params()).

%% @doc Calculates a public key from the given `PrivateKey'.
%%
%% This function is only valid for curves returned by `supports_from_private/0'.
%% @see supports_from_private/0
%% @see supports_from_private/1
-spec from_private(PrivateKey :: ecies:private_key(), ecies:ecies_params()) -> ecies:public_key().
from_private(PrivKey, #{ curve := NamedCurve } = _Params) when NamedCurve == x25519; NamedCurve == x448 ->
  error(badarg, [PrivKey, #{ curve => NamedCurve }]);
from_private(PrivKey, #{ curve := NamedCurve } = Params) ->
  {_Field, _Curve, BasePoint, _Order, _Cofactor} = crypto_ec_curves:curve(NamedCurve),
  mul(BasePoint, PrivKey, Params).

%% @doc
%% Calculates the multiplication of an elliptic curve point given by `PublicKey' by a scalar given by `PrivateKey'.
%% @equiv mul(PublicKey, PrivateKey, ecies:default_params())
-spec mul(PublicKey :: ecies:public_key(), PrivateKey :: ecies:private_key()) -> ecies:public_key().
mul(PublicKey, PrivateKey) ->
  mul(PublicKey, PrivateKey, ecies:default_params()).

%% @doc
%% Calculates the multiplication of an elliptic curve point given by `PublicKey' by a scalar given by `PrivateKey'.
%%
%% This function is only valid for curves returned by `supports_decompress/0'.
%% @see supports_decompress/0
%% @see supports_decompress/1
-spec mul(ecies:public_key(), ecies:private_key(), ecies:ecies_params()) -> ecies:public_key().
mul(PublicKey, PrivateKey, #{ curve := NamedCurve } = Params) ->
  P = b2p(PublicKey, Params),
  S = crypto:bytes_to_integer(PrivateKey),
  C = curve_details(NamedCurve),
  JP  = to_jacobian(P, C),
  JPS = jacobian_mul(JP, S, C),
  R = from_jacobian(JPS, C),
  p2b(R, Params).

%% @doc Returns the number of bits required for the binary representation of a single coordinate of a point
%% on a given elliptic curve.
-spec point_bits(ecies:named_curve()) -> integer().
point_bits(NamedCurve) ->
  case crypto_ec_curves:curve(NamedCurve) of
    {{prime_field, BinP}, _, _, _, _} -> byte_size(BinP) * 8;
    {{characteristic_two_field, Bits, _}, _, _, _,_} -> ((Bits + 7) div 8) * 8
  end.

% priv
-spec curve_details(ecies:named_curve()) -> {A :: integer(), B :: integer(), P :: integer(), N :: integer()}.
curve_details(NamedCurve) ->
  {BinA, BinB, BinP, BinN} =
    case crypto_ec_curves:curve(NamedCurve) of
      {{prime_field, BinP0}, {BinA0, BinB0, _BinSeed}, _BinG, BinN0, _BinH} -> {BinA0, BinB0, BinP0, BinN0};
      _ -> error(badarg, [NamedCurve])
    end,
  {
    crypto:bytes_to_integer(BinA),
    crypto:bytes_to_integer(BinB),
    crypto:bytes_to_integer(BinP),
    crypto:bytes_to_integer(BinN)
  }.

b2p(<<Tag, _/binary>> = Key, #{ curve := NamedCurve } = Params) when Tag == 2; Tag == 3; Tag == 4 ->
  Pbits = point_bits(NamedCurve),
  case decompress(Key, Params) of
    <<4, X:Pbits, Y:Pbits>> ->
      {X, Y};
    _ ->
      error(badarg, [Key, NamedCurve])
  end.

p2b({Px, Py}, #{ curve := NamedCurve } = Params) ->
  Pbits = point_bits(NamedCurve),
  Bin = <<4,Px:Pbits, Py:Pbits>>,
  case maps:get(compress_pubkey, Params, true) of
    true -> compress(Bin, Params);
    false -> Bin
  end.

mod(X, N) ->
  case X rem N of
    R when R < 0 -> R + N;
    R -> R
  end.

inv(X, _N) when X == 0 -> 
  0;
inv(X, N) when X > N -> 
  inv2(1, 0, X rem N, N);
inv(X, N) -> 
  case inv2(1, 0, X, N) of
    I when I < 0 -> I + N;
    I -> I
  end.

inv2(A, B, X, N) when X > 1 ->
  Q = N div X,
  R = N - Q*X,
  inv2(B - Q*A, A, R, X);
inv2(A, _B, _X, _N) ->
  A.

% https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
to_jacobian({X, Y}, _C) ->
  {X, Y, 1}.

from_jacobian({X, Y, 1}, _C) ->
  {X, Y};
from_jacobian({X, Y, Z}, {_CA, _CB, CP, _CN}) ->
  IZ = inv(Z, CP),
  IZ2 = IZ * IZ,
  IZ3 = IZ2 * IZ,
  {mod(X * IZ2, CP), mod(Y * IZ3, CP)}.

jacobian_add({_Px, Py, _Pz}, Q, _C) when Py == 0 -> Q;
jacobian_add(P, {_Qx, Qy, _Qz}, _C) when Qy == 0 -> P;
jacobian_add({Px, Py, Pz} = P, {Qx, Qy, Qz}, {_CA, _CB, CP, _CN} = C) ->
  Qz2 = Qz*Qz,
  Pz2 = Pz*Pz,
  U1 = mod(Px * Qz2, CP),
  U2 = mod(Qx * Pz2, CP),
  S1 = mod(Py * Qz2 * Qz, CP),
  S2 = mod(Qy * Pz2 * Pz, CP),
  if
    U1 == U2 andalso S1 /= S2 ->
     {0, 0, 1};
    U1 == U2 ->
      jacobian_double(P, C);
    true ->
      H = U2 - U1,
      R = S2 - S1,
      H2 = mod(H * H, CP),
      H3 = mod(H * H2, CP),
      U1H2 = mod(U1 * H2, CP),
      X = mod(R * R - H3 - 2 * U1H2, CP),
      Y = mod(R * (U1H2 - X) - S1 * H3, CP),
      Z = mod(H * Pz * Qz, CP),
      {X, Y, Z}
  end.

jacobian_double({_X, 0 = _Y, _Z}, _C) -> 
  {0, 0, 1};
jacobian_double({Px, Py, Pz}, {CA, _CB, CP, _CN}) ->
  Px2 = mod(Px * Px, CP),
  Py2 = mod(Py * Py, CP),
  Pz2 = mod(Pz * Pz, CP),
  Py4 = mod(Py2 * Py2, CP),
  Pz4 = mod(Pz2 * Pz2, CP),
  S = mod(4 * Px * Py2, CP),
  M = mod(3 * Px2 + CA * Pz4, CP),
  X = mod(M * M - 2 * S, CP),
  Y = mod(M * (S - X) - 8 * Py4, CP),
  Z = mod(2 * Py * Pz, CP),
  {X, Y, Z}.

jacobian_mul({_X, 0 = _Y, _Z}, _S, _C) -> {0, 0, 1};
jacobian_mul(_P, 0 = _S, _C) -> {0, 0, 1};
jacobian_mul(P, S, {_CA, _CB, _CP, CN} = C) when S < 0; S > CN ->
  jacobian_montgomery_mul(P, mod(S, CN), C);
jacobian_mul(P, S, C) ->
  jacobian_montgomery_mul(P, S, C).

% Double and add (faster, but not recommended)
% jacobian_double_and_add_mul(P, S, _C) when S == 1 -> P;
% jacobian_double_and_add_mul(P, S, C) when S band 1 == 0 -> jacobian_double(jacobian_double_and_add_mul(P, S div 2, C), C);
% jacobian_double_and_add_mul(P, S, C) -> jacobian_add(jacobian_double(jacobian_double_and_add_mul(P, S div 2, C), C), P, C).

% Montgomery ladder
jacobian_montgomery_mul(P, S, C) ->
  D = lists:dropwhile(fun(Bit) -> Bit == 0 end, [Bit || <<Bit:1>> <= binary:encode_unsigned(S)]),
  {R, _} = lists:foldl(
    fun(Di, {R0, R1}) ->
      {NR0, NR1} = case Di of
        1 -> {jacobian_add(R0, R1, C), jacobian_double(R1, C)};
        0 -> {jacobian_double(R0, C), jacobian_add(R0, R1, C)}
      end,
      {NR0, NR1}
    end, {{0, 0, 1}, P}, D),
  R.