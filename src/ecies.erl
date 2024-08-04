%% @doc This module contains functions for generating EC keys and encrypting, decrypting data using
%% Elliptic Curve Integrated Encryption Scheme (ECIES).
%%
%%
-module(ecies).

-export([
  generate_key/0,
  public_encrypt/2,
  private_decrypt/2,
  
  generate_key/1,
  public_encrypt/3,
  private_decrypt/3,

  default_params/0,
  supports/1
]).

-export([
  kdf/4
]).

-export_type([
  keypair/0,
  public_key/0,
  private_key/0,
  named_curve/0,
  ecies_params/0,
  cipher/0,
  digest_type/0,
  kdf_type/0,
  mac_type/0,
  encrypted_data/0
]).

-type named_curve() :: crypto:ec_named_curve() | x25519 | x448.
-type digest_type() :: sha | % SHA-1
                       sha224 | sha256 | sha384 | sha512 |
                       sha3_224 | sha3_256 | sha3_384 | sha3_512 |
                       ripemd160 | blake2b | blake2s |
                       md5 | md4 | sm3.
-type cipher()      :: 'xor' | atom(). % all ciphers supported by crypto
-type cmac_cipher() :: aes_cbc |
                       aes_128_cbc |
                       aes_192_cbc |
                       aes_256_cbc.
-type aead_cipher() :: aes_ccm | aes_gcm |
                       aes_128_ccm | aes_128_gcm |
                       aes_192_ccm | aes_192_gcm |
                       aes_256_ccm | aes_256_gcm |
                       chacha20_poly1305.
-type public_key()  :: binary().
-type private_key() :: binary().
-type keypair()     :: {public_key(), private_key()}.
-type plain_text()  :: iodata().
-type cipher_text() :: binary().
-type auth_tag()    :: binary(). % message authentication tag
-type encrypted_data() :: binary() | {public_key(), cipher_text(), MAC :: auth_tag()}.
-type kdf_type()    :: {hkdf, digest_type()} |
                       {kdf, digest_type()}  |
                       {concat_kdf, digest_type()}  |
                       kdf_fun().
-type kdf_fun()     :: fun((SharedKey :: binary(), Info :: binary(), Length :: pos_integer()) -> Result :: binary()).
-type mac_type()    :: {hmac, digest_type(), mac_bits()} |
                       {cmac, cmac_cipher(), mac_bits()} |
                       {aead, mac_bits()}.
-type mac_bits()    :: pos_integer() | default.

-type ecies_params() :: #{
    curve := named_curve(),
    compress_pubkey => boolean(), % use ec point compression for public key when generating ephemeral key - default true

    cipher => cipher(),   % default aes_256_cbc
    kdf => kdf_type(), % default {hkdf, sha256}
    mac => mac_type(), % default {hmac, sha256, 256}
    s1  => binary(),   % shared info 1 (used with kdf) - default empty
    s2  => binary(),   % shared info 2 (used with mac), used as AAD for aead mac - default empty

    key => keypair(),  % if specified it is used in encryption instead of generating ephemeral key
    iv  => binary() | random | fun(),       % if specified used instead of default 0000..00 one

    embedded_iv => boolean(),
    generate_key => fun(),
    shared_key => binary() | fun(),
    derive_keys => fun(),
    prepare_payload => fun(),
    decode => fun(),
    encode => as_tuple | raw | fun(),  % if true returns tuple {PublicKey, CipherText, MAC} instead of binary - default false

    % keys below are filled automatically during encryption / decryption
    others_public_key => public_key(),
    _ => _
  }.


%% @doc Returns list of supported curves, ciphers and digest types (hashs) that can be used with `ecies' library
-spec supports(hashs)  -> [digest_type()];
              (curves) -> [named_curve()];
              (ciphers) -> [cipher()];
              (cmac_ciphers) -> [cmac_cipher()];
              (aead_ciphers) -> [aead_cipher()].
supports(hashs) ->
  % shake hashes seems to not work well with crypto:mac
  crypto:supports(hashs) -- [shake128, shake256];
supports(curves) ->
  % we do support x25519 and x448, 'ed' named versions are used for signatures and we need DH here
  crypto:supports(curves) -- [ed25519, ed448];
supports(ciphers) ->
  % additionally to all ciphers supported by crypto library we also support 'xor' one used e.g. in IEEE Std 1609.2a for
  % AES key wrapping using ECIES
  ['xor' | crypto:supports(ciphers) -- supports(aead_ciphers)];
supports(cmac_ciphers) ->
  [aes_cbc, aes_128_cbc, aes_192_cbc, aes_256_cbc];
supports(aead_ciphers) ->
  % AEAD ciphers should be used together with mac {aead, MacBits} because they are providing authentication tag
  % themselves
  [aes_ccm, aes_gcm, aes_128_ccm, aes_128_gcm, aes_192_ccm, aes_192_gcm, aes_256_ccm, aes_256_gcm, chacha20_poly1305].


%% @doc Default elliptic curve `secp256k1' and set of algorithms used for ECIES encryption/decryption.
%%
%% By default ANSI-X9.63 key derivation function is used with AES-256 CBC encryption and 
%% HMAC-SHA256 with 256 bits output authentication tag
-spec default_params() -> ecies_params().
default_params() ->
  #{
    curve  => secp256k1,
    kdf    => {kdf, sha256},       % ANSI-X9.63 key derivation
    cipher => aes_256_cbc,
    mac    => {hmac, sha256, 256}  % HMAC SHA256 with 256 bits (32 bytes) output
  }.


%% @doc Generates a new key pair for default `secp256k1' curve
%%
%% @equiv generate_key(default_params())
-spec generate_key() -> keypair().
generate_key() ->
  generate_key(default_params()).

%% @doc Generates a new key pair for elliptic curve specified in `Params' under `curve' key.
-spec generate_key(#{ curve := named_curve(), _ => _ }) -> keypair().
generate_key(#{ curve := Curve } = Params0) ->
  Params = maps:merge(default_params(), Params0),
  CompressPubKey = maps:get(compress_pubkey, Params, true),
  Type = dh_type(Curve),
  {Pub, Priv} = crypto:generate_key(Type, Curve),
  case CompressPubKey andalso Type == ecdh of
    true  -> {ecies_pubkey:compress(Pub, Params), Priv};
    false -> {Pub, Priv}
  end.


%% @doc Encrypts the `PlainText' using the `OthersPublicKey' and returns the `CipherText'
%%
%% Uses the default curve `secp256k1' and other params returned from `default_params/0'
%%
%% @equiv public_encrypt(OthersPublicKey, PlainText, default_params())
-spec public_encrypt(OthersPublicKey :: public_key(), PlainText :: plain_text()) -> CipherText :: binary().
public_encrypt(OthersPublicKey, PlainText) ->
  public_encrypt(OthersPublicKey, PlainText, default_params()).

%% @doc Decrypts the `CipherData' using the `PrivateKey' and returns the `PlainText'
%%
%% Uses the default curve `secp256k1' and other params returned from `default_params/0'
%%
%% @equiv private_decrypt(PrivateKey, CipherData, default_params())
-spec private_decrypt(private_key(), encrypted_data()) -> binary().
private_decrypt(PrivateKey, CipherData) ->
  private_decrypt(PrivateKey, CipherData, default_params()).

%% @doc Encrypts the `PlainText' using the `OthersPublicKey' and returns encrypted data (binary cipher text by default).
%%
%% Uses the set of algorithms and elliptic curve defined in `Params' argument  
-spec public_encrypt(OthersPublicKey :: public_key(), plain_text(), ecies_params()) -> encrypted_data().
public_encrypt(OthersPublicKey, PlainText, #{} = Params0) ->
  State0 = init_state(Params0#{ others_public_key => OthersPublicKey, plain_text => PlainText }),
  {ok, State1} = generate_ephemeral_key(State0),
  {ok, State2} = compute_shared_key(State1),
  {ok, State3} = prepare_encryption_payload(State2),
  {ok, State4} = derive_keys(State3),
  {ok, State5} = prepare_iv(State4),
  {ok, State6} = encrypt_payload(State5),
  {ok, State7} = prepare_payload_for_authentication(State6),
  {ok, State8} = authenticate_payload(State7),
  encode_cipher_data(State8).

%% @doc Decrypts the `CipherData' using the `PrivateKey' and returns the `PlainText'
%%
%% Uses the set of algorithms and elliptic curve defined in `Params' argument  
-spec private_decrypt(private_key(), encrypted_data(), ecies_params()) -> binary() | error.
private_decrypt(PrivateKey, CipherData, #{} = Params0) ->
  try
    State0 = init_state(Params0#{ key => {undefined, PrivateKey}, cipher_data => CipherData }),
    {ok, State1} = decode_cipher_data(State0),
    {ok, State2} = compute_shared_key(State1),
    {ok, State3} = prepare_cipher_text_for_decryption(State2),
    {ok, State4} = derive_keys(State3),
    {ok, State5} = authenticate_payload(State4),
    {ok, State6} = check_expected_mac(State5),
    {ok, State7} = prepare_iv(State6),
    {ok, State8} = decrypt_cipher_text(State7),
    maps:get(plain_text, State8)
  catch
    error:{badmatch, error} -> error;
    error:{badarg, _, _} -> error
  end.

% priv
init_state(#{} = Params0) ->
  ExtendedDefaults = (default_params())#{
    compress_pubkey => true,
    s1 => <<>>,
    s2 => <<>>
  },
  Params1 = maps:merge(ExtendedDefaults, Params0),
  Cipher  = maps:get(cipher, Params1),
  % random iv implies embedded_iv = true
  EmbeddedIv = maps:get(embedded_iv, Params1, maps:get(iv, Params1, undefined) == random),
  #{key_length := KeyLen,
    iv_length := IVLen,
    prop_aead := UseAEAD
  } = cipher_info(Cipher),
  Params2 = Params1#{
    enc_key_length => KeyLen,
    iv_length  => IVLen,
    embedded_iv => EmbeddedIv,
    use_aead => UseAEAD
  },
  Params2#{
    mac_length     => mac_length(Params2),
    mac_key_length => mac_key_length(Params2)
 }.

% priv
encode_cipher_data(#{ encode := debug } = State) ->
  State;
encode_cipher_data(#{ encode := as_tuple } = State) ->
  #{key := {PublicKey, _PrivateKey}, payload := Payload, mac := MAC} = State,
  {PublicKey, Payload, MAC};
encode_cipher_data(#{ encode := EncodeFun } = State) when is_function(EncodeFun) ->
  EncodeFun(State);
encode_cipher_data(#{ embedded_key := false } = State) ->
  #{ payload := Payload, mac := MAC} = State,
  <<Payload/binary, MAC/binary>>;
encode_cipher_data(#{} = State) ->
  #{ key := {PublicKey, _PrivateKey}, payload := Payload, mac := MAC} = State,
  <<PublicKey/binary, Payload/binary, MAC/binary>>.


% priv
decode_cipher_data(#{ decode := DecodeFun } = State) when is_function(DecodeFun) ->
  DecodeFun(State);
decode_cipher_data(#{} = State) ->
  #{ curve := Curve, cipher_data := CipherData, mac_length := MacLen } = State,
  case CipherData of
    {OthersPublicKey, Payload, MAC} ->
      {ok, State#{others_public_key => OthersPublicKey, expected_mac => MAC, payload => Payload}};
    _ when is_binary(CipherData) ->
      case maps:get(embedded_key, State, true) of
        true ->
          PublicLen = public_key_length(Curve, CipherData),
          PayloadLen = byte_size(CipherData) - PublicLen - MacLen,
          <<OthersPublicKey:PublicLen/bytes, Payload:PayloadLen/bytes, MAC:MacLen/bytes>> = CipherData,
          {ok, State#{others_public_key => OthersPublicKey, expected_mac => MAC, payload => Payload}};
        false ->
          PayloadLen = byte_size(CipherData) - MacLen,
          <<Payload:PayloadLen/bytes, MAC:MacLen/bytes>> = CipherData,
          {ok, State#{expected_mac => MAC, payload => Payload}}
      end
  end.

% priv
prepare_cipher_text_for_decryption(#{ cipher_text := _} = State) ->
  {ok, State};
prepare_cipher_text_for_decryption(#{ embedded_iv := true } = State) ->
  #{ iv_length := IVLen, payload := Payload } = State,
  <<IV:IVLen/bytes, CipherText/binary>> = Payload,
  {ok, State#{ iv => IV, cipher_text => CipherText }};
prepare_cipher_text_for_decryption(#{} = State) ->
  #{ payload := Payload } = State,
  {ok, State#{ cipher_text => Payload }}.


% priv
-spec generate_ephemeral_key(#{ generate_key => _, key => _, _ => _}) -> {ok, #{ key := keypair(), _ => _}}.
generate_ephemeral_key(#{ generate_key := GenerateKeyFun } = State) when is_function(GenerateKeyFun) ->
  GenerateKeyFun(State);
generate_ephemeral_key(#{ key :=  _} = State) ->
  {ok, State};
generate_ephemeral_key(#{} = State) ->
  {ok, State#{ key => generate_key(State) }}.

% priv
compute_shared_key(#{ shared_key := SharedKeyFun } = State) when is_function(SharedKeyFun) ->
  SharedKeyFun(State);
compute_shared_key(#{ shared_key := _} = State) ->
  {ok, State};
compute_shared_key(State) ->
  #{ curve := Curve, others_public_key := OthersPublicKey, key := {_PublicKey, PrivateKey} } = State,
  try
    Type = dh_type(Curve),
    SharedKey = crypto:compute_key(Type, OthersPublicKey, PrivateKey, Curve),
    {ok, State#{ shared_key => SharedKey }}
  catch _:_ ->
    error
  end.

% priv
fix_xor_enc_key_lenght(#{ cipher := 'xor', encryption_payload := Payload } = State) ->
  State#{enc_key_length => byte_size(Payload)};
fix_xor_enc_key_lenght(#{ cipher := 'xor', cipher_text := Payload } = State) ->
  State#{enc_key_length => byte_size(Payload)};
fix_xor_enc_key_lenght(State) ->
  State.

% priv
derive_keys(#{ derive_keys := DeriveKeysFun } = State) when is_function(DeriveKeysFun) ->
  DeriveKeysFun(maps:remove(derive_keys, fix_xor_enc_key_lenght(State)));
derive_keys(#{ enc_key := _, mac_key := _ } = State) ->
  {ok, State};
derive_keys(State0) ->
  State = fix_xor_enc_key_lenght(State0),
  #{ shared_key := SharedKey, s1 := Info, enc_key_length := EncKeyLen, mac_key_length := MacKeyLen} = State,
  <<EncKey:EncKeyLen/bytes, MacKey:MacKeyLen/bytes>> = kdf(SharedKey, Info, EncKeyLen + MacKeyLen, State),
  {ok, State#{ enc_key => EncKey, mac_key => MacKey }}.

% priv
prepare_iv(#{ iv := IVFun } = State) when is_function(IVFun) ->
  IVFun(State);
prepare_iv(#{ iv := IV } = State) when is_binary(IV) ->
  {ok, State};
prepare_iv(#{ iv := random } = State) ->
  IVLen = maps:get(iv_length, State),
  {ok, State#{ iv => crypto:strong_rand_bytes(IVLen), embedded_iv => true }};
prepare_iv(#{} = State) ->
  IVLen = maps:get(iv_length, State),
  {ok, State#{ iv => <<0:IVLen/unit:8>>}}.

% priv
prepare_encryption_payload(#{} = State) ->
  PlainText = maps:get(plain_text, State),
  {ok, State#{ encryption_payload => PlainText }}.

% priv
encrypt_payload(#{ use_aead := false } = State) ->
  #{cipher := Cipher, enc_key := EncKey, iv := IV, encryption_payload := EncryptionPayload} = State,
  CipherText =
    case Cipher of
      'xor' -> crypto:exor(EncKey, EncryptionPayload);
      _     -> crypto:crypto_one_time(Cipher, EncKey, IV, EncryptionPayload, [{encrypt, true}, {padding, pkcs_padding}])
    end,
  {ok, State#{ cipher_text => CipherText }};
encrypt_payload(#{ use_aead := true } = State) ->
  #{cipher := Cipher, enc_key := EncKey, iv := IV, encryption_payload := EncryptionPayload,
    s2 := Info, mac_length := MacLen} = State,
  AAD = maps:get(aad, State, Info),
  {CipherText, MAC} = crypto:crypto_one_time_aead(Cipher, EncKey, IV, EncryptionPayload, AAD, MacLen, true),
  {ok, State#{ cipher_text => CipherText, mac => MAC }}.

% priv
decrypt_cipher_text(#{ use_aead := false } = State) ->
  #{cipher := Cipher, cipher_text := CipherText, enc_key := EncKey, iv := IV} = State,
  PlainText =
    case Cipher of
      'xor' -> crypto:exor(EncKey, CipherText);
      _     -> crypto:crypto_one_time(Cipher, EncKey, IV, CipherText, [{encrypt, false}, {padding, pkcs_padding}])
    end,
  {ok, State#{ plain_text => PlainText }};
decrypt_cipher_text(#{ use_aead := true } = State) ->
  #{cipher := Cipher, cipher_text := CipherText, enc_key := EncKey, iv := IV } = State,
  AAD = maps:get(aad, State, maps:get(s2, State)),
  PlainText = crypto:crypto_one_time_aead(Cipher, EncKey, IV, CipherText, AAD, maps:get(expected_mac, State), false),
  case PlainText of
    error -> error;
    _ -> {ok, State#{ plain_text => PlainText }}
  end.

% priv
prepare_payload_for_authentication(#{ prepare_payload := PreparePayloadFun } = State) ->
  PreparePayloadFun(State);
prepare_payload_for_authentication(#{ embedded_iv := true } = State) ->
  #{ iv := IV, cipher_text := CipherText } = State,
  {ok, State#{ payload => <<IV/binary, CipherText/binary>> }};
prepare_payload_for_authentication(State) ->
  #{ cipher_text := CipherText } = State,
  {ok, State#{ payload => CipherText}}.
  
% priv
authenticate_payload(#{ use_aead := true } = State) ->
  {ok, State};
authenticate_payload(State) ->
  #{ payload := Payload, mac_key := MacKey, s2 := Info  } = State,
  MAC = mac(MacKey, Payload, Info, State),
  {ok, State#{ mac => MAC }}.

% priv
check_expected_mac(#{ use_aead := true } = State) ->
  {ok, State};
check_expected_mac(State) ->
  #{ mac := MAC, expected_mac := ExpectedMAC } = State,
  case MAC == ExpectedMAC of
    true -> {ok, State};
    false -> error
  end.

%% @doc Executes Key Derivation Function for given arguments using function defined in `Params'
%% @private
kdf(SharedKey, Info, Length, #{kdf := {hkdf, Hash}} = Params) ->
  Salt = maps:get(hkdf_salt, Params, <<>>),
  ecies_kdf:hkdf(Hash, SharedKey, Salt, Info, Length);
kdf(SharedKey, Info, Length, #{kdf := {kdf, Hash}} = _Params) ->
  ecies_kdf:kdf(Hash, SharedKey, Info, Length);
kdf(SharedKey, Info, Length, #{kdf := {concat_kdf, Hash}} = _Params) ->
  ecies_kdf:concat_kdf(Hash, SharedKey, Info, Length);
kdf(SharedKey, Info, Length, #{ kdf := Fun } = _Params) when is_function(Fun, 3) ->
  Fun(SharedKey, Info, Length).

cipher_info('xor') ->
  #{ key_length => 0, iv_length => 0, prop_aead => false };
cipher_info(Cipher) ->
  crypto:cipher_info(Cipher).

mac(Key, InText, Info, #{mac := {hmac, Hash, default}} = _Params) ->
  crypto:mac(hmac, Hash, Key, <<InText/binary, Info/binary>>);
mac(Key, InText, Info, #{mac := {hmac, Hash, MacBits}} = _Params) ->
  crypto:macN(hmac, Hash, Key, <<InText/binary, Info/binary>>, MacBits div 8);
mac(Key, InText, Info, #{mac := {cmac, Cipher, default}} = _Params) ->
  crypto:mac(cmac, Cipher, Key, <<InText/binary, Info/binary>>);
mac(Key, InText, Info, #{mac := {cmac, Cipher, MacBits}} = _Params) ->
  crypto:macN(cmac, Cipher, Key, <<InText/binary, Info/binary>>, MacBits div 8);
mac(_Key, _InText, _Info, _Params) ->
  error(badarg).

mac_key_length(#{ use_aead := true } = _Params)               -> 0;
mac_key_length(#{ mac := {hmac, Hash, _MacBits}} = _Params)   -> maps:get(size, crypto:hash_info(Hash));
mac_key_length(#{ mac := {cmac, Cipher, _MacBits}} = _Params) -> maps:get(key_length, crypto:cipher_info(Cipher)).

mac_length(#{ use_aead := true, mac := {aead, default}} = _Params) -> 12;
mac_length(#{ use_aead := true, mac := {aead, MacBits}} = _Params) -> MacBits div 8;
mac_length(#{ use_aead := true } = Params)                -> error(badarg, [maps:with([cipher, mac], Params)]);
mac_length(#{ mac := {hmac, Hash, default}} = _Params)    -> maps:get(size, crypto:hash_info(Hash));
mac_length(#{ mac := {hmac, _Hash, MacBits}} = _Params)   -> MacBits div 8;
mac_length(#{ mac := {cmac, Cipher, default}} = _Params)  -> maps:get(block_size, crypto:cipher_info(Cipher));
mac_length(#{ mac := {cmac, _Cipher, MacBits}} = _Params) -> MacBits div 8.

dh_type(x25519) -> eddh;
dh_type(x448)   -> eddh;
dh_type(_Curve) -> ecdh.

public_key_length(x25519, _Data) -> 32;
public_key_length(x448, _Data)   -> 56;
public_key_length(NamedCurve, Data) ->
  try
    PointSize = ecies_pubkey:point_bits(NamedCurve) div 8,
    case binary:first(Data) of
      4 -> 1 + 2 * PointSize;
      N when N == 2; N == 3 -> 1 + PointSize
    end
  catch _:_ ->
    error(badarg, [NamedCurve])
  end.
