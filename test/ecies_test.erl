-module(ecies_test).

-include_lib("eunit/include/eunit.hrl").

-define(MESSAGE, <<"top secret message">>).

flip_random_bit(Bin) ->
  Bits = bit_size(Bin),
  N = rand:uniform(Bits),
  X = <<0:(N-1), 1:1, 0:(Bits-N)>>,
  crypto:exor(X, Bin).

default_test() ->
  % Bob generates keys
  {BobPublicKey, BobPrivateKey} = ecies:generate_key(),
  % Alice knowing Bob's public key encrypts a message for him
  Data = ecies:public_encrypt(BobPublicKey, ?MESSAGE),
  % Bob is able to decrypt the message using his private key
  ?assertEqual(?MESSAGE, ecies:private_decrypt(BobPrivateKey, Data)).

static_keys_with_random_iv_test() ->
  {AlicePublicKey, AlicePrivateKey} = ecies:generate_key(),
  {BobPublicKey, BobPrivateKey} = ecies:generate_key(),

  % It is crucial to use unique iv for subsequent encryptions with same key (static Alice key here)
  % NOTE: using random IV indirectly forces embedded_iv = true
  % Alice's public key is not embedded in the payload (embedded_key => false)
  AliceParams = #{ key => {AlicePublicKey, AlicePrivateKey}, iv => random, embedded_key => false },
  {AlicePublicKey, _Payload, _MAC} = ecies:public_encrypt(BobPublicKey, ?MESSAGE, AliceParams#{ encode => as_tuple }),
  Data = ecies:public_encrypt(BobPublicKey, ?MESSAGE, AliceParams),

  % Alice's public key is not embedded in the payload (embedded_key => false)
  BobParams = #{ others_public_key => AlicePublicKey, iv => random, embedded_key => false },
  ?assertEqual(?MESSAGE, ecies:private_decrypt(BobPrivateKey, Data, BobParams)).

static_keys_with_deterministic_iv_test() ->
  {AlicePublicKey, AlicePrivateKey} = ecies:generate_key(),
  {BobPublicKey, BobPrivateKey} = ecies:generate_key(),

  % It is crucial to use unique iv for subsequent encryptions with same key (static Alice key here)
  % Using deterministic IV based on computed shared key could be a safe choice to not have to embed IV in payload
  IVFun =
    fun(#{ shared_key := SharedKey, iv_length := IVLen } = State) ->
      IV = ecies:kdf(SharedKey, <<"iv">>, IVLen, State),
      {ok, State#{ iv => IV}}
    end,

  AliceParams = #{ key => {AlicePublicKey, AlicePrivateKey}, iv => IVFun, embedded_key => false },
  {AlicePublicKey, _Payload, _MAC} = ecies:public_encrypt(BobPublicKey, ?MESSAGE, AliceParams#{ encode => as_tuple }),
  Data = ecies:public_encrypt(BobPublicKey, ?MESSAGE, AliceParams),

  BobParams = #{ others_public_key => AlicePublicKey, iv => IVFun, embedded_key => false },
  ?assertEqual(?MESSAGE, ecies:private_decrypt(BobPrivateKey, Data, BobParams)).

curve_test_() ->
  % all supported curves should work
  SupportedCurves = ecies:supports(curves),
  [
    {
      atom_to_list(Curve) ++ " curve " ++ case CompressPubKey of true -> "with point compression"; false -> "" end,
      fun() -> curve_check(Curve, CompressPubKey) end
    } || Curve <- SupportedCurves, CompressPubKey <- [false, true]
  ].

cipher_test_() ->
  % all supported ciphers should work
  SupportedCiphers = ecies:supports(ciphers),
  [
    {
        atom_to_list(Cipher) ++ "cipher",
        fun() -> cipher_check(Cipher) end
    } || Cipher <- SupportedCiphers
  ].

aead_cipher_test_() ->
  SupportedCiphers =ecies:supports(aead_ciphers),
  [
    {
      lists:flatten(io_lib:format("cmac with ~s and ~p output", [Cipher, MacBits])),
      fun() -> aead_check(Cipher, MacBits) end
    } || Cipher <- SupportedCiphers, MacBits <- [32, 64, 96, 128, default]
  ].

kdf_test_() ->
  SupportedHashs = ecies:supports(hashs),
  [
    {
      atom_to_list(Type) ++ " with " ++ atom_to_list(Hash),
      fun() -> kdf_check({Type, Hash}) end
    } || Type <- [kdf, hkdf, concat_kdf], Hash <- SupportedHashs
  ].

hmac_test_() ->
  SupportedHashs = ecies:supports(hashs),
  [
    {
      lists:flatten(io_lib:format("hmac with ~s and ~p output", [Hash, MacBits])),
      fun() -> mac_check({hmac, Hash, MacBits}) end
    } || Hash <- SupportedHashs, MacBits <- [32, 64, 96, 128, default]
  ].

cmac_test_() ->
  SupportedCiphers = ecies:supports(cmac_ciphers),
  [
    {
      lists:flatten(io_lib:format("cmac with ~s and ~p output", [Cipher, MacBits])),
      fun() -> mac_check({cmac, Cipher, MacBits}) end
    } || Cipher <- SupportedCiphers, MacBits <- [32, 64, 96, 128, default]
  ].

tuple_result_test() ->
  Params = #{ encode => as_tuple },
  {PublicKey, PrivateKey} = ecies:generate_key(),
  Data = ecies:public_encrypt(PublicKey, ?MESSAGE, Params),
  ?assertEqual(?MESSAGE, ecies:private_decrypt(PrivateKey, Data, Params)),
  ?assertMatch({_, _, _}, Data),
  {ECIESPubKey, CipherText, MAC} = Data,
  EncData = <<ECIESPubKey/binary, CipherText/binary, MAC/binary>>,
  ?assertEqual(?MESSAGE, ecies:private_decrypt(PrivateKey, EncData, Params)).

custom_kdf_test() ->
  Params = #{ kdf => fun(SharedKey, Info, 64) -> crypto:mac(hmac, sha512, SharedKey, Info) end},
  {PublicKey, PrivateKey} = ecies:generate_key(),
  Data = ecies:public_encrypt(PublicKey, ?MESSAGE, Params),
  ?assertEqual(?MESSAGE, ecies:private_decrypt(PrivateKey, Data, Params)).

invalid_authentication_tag_test() ->
  lists:foreach(
    fun(Params) ->
      {PublicKey, PrivateKey} = ecies:generate_key(),
      {ECIESPubKey, Payload, MAC} = ecies:public_encrypt(PublicKey, ?MESSAGE, Params#{ encode => as_tuple }),
      InvalidMAC = flip_random_bit(MAC),
      ?assertEqual(error, ecies:private_decrypt(PrivateKey, {ECIESPubKey, Payload, InvalidMAC}, Params))
    end,
    [#{}, #{ cipher => aes_256_gcm, mac => {aead, default}}]).

invalid_payload_test() ->
  lists:foreach(
    fun(Params) ->
      {PublicKey, PrivateKey} = ecies:generate_key(),
      {ECIESPubKey, Payload, MAC} = ecies:public_encrypt(PublicKey, ?MESSAGE, Params#{encode => as_tuple}),
      InvalidPayload = flip_random_bit(Payload),
      ?assertEqual(error, ecies:private_decrypt(PrivateKey, {ECIESPubKey, InvalidPayload, MAC}, Params))
    end,
    [#{}, #{ cipher => aes_256_gcm, mac => {aead, default}}]).

invalid_pubkey_test() ->
  lists:foreach(
    fun(Params) ->
      {PublicKey, PrivateKey} = ecies:generate_key(),
      {ECIESPubKey, Payload, MAC} = ecies:public_encrypt(PublicKey, ?MESSAGE, Params#{ encode => as_tuple }),
      <<FirstByte,Rest/binary>> = ECIESPubKey,
      InvalidPubKey = <<FirstByte, (flip_random_bit(Rest))/binary>>,
      ?assertEqual(error, ecies:private_decrypt(PrivateKey, {InvalidPubKey, Payload, MAC}, Params)),
      TooShortPubKey = binary:part(ECIESPubKey, 1, byte_size(ECIESPubKey) - 1),
      ?assertEqual(error, ecies:private_decrypt(PrivateKey, {TooShortPubKey, Payload, MAC}, Params))
    end,
    [#{}, #{ cipher => aes_256_gcm, mac => {aead, default}}]).

curve_check(Curve, CompressPubKey) ->
  Params = #{ curve => Curve, compress_pubkey => CompressPubKey},
  {PublicKey, PrivateKey} = ecies:generate_key(Params),
  Data = ecies:public_encrypt(PublicKey, ?MESSAGE, Params),
  ?assertEqual(?MESSAGE, ecies:private_decrypt(PrivateKey, Data, Params)).

cipher_check(Cipher) ->
  Params = #{ cipher => Cipher },
  {PublicKey, PrivateKey} = ecies:generate_key(),
  Data = ecies:public_encrypt(PublicKey, ?MESSAGE, Params),
  ?assertEqual(?MESSAGE, ecies:private_decrypt(PrivateKey, Data, Params)).

kdf_check(Kdf) ->
  Params = #{ kdf => Kdf },
  {PublicKey, PrivateKey} = ecies:generate_key(),
  Data = ecies:public_encrypt(PublicKey, ?MESSAGE, Params),
  ?assertEqual(?MESSAGE, ecies:private_decrypt(PrivateKey, Data, Params)).

mac_check(Mac) ->
  Params = #{ mac => Mac },
  {PublicKey, PrivateKey} = ecies:generate_key(),
  Data = ecies:public_encrypt(PublicKey, ?MESSAGE, Params),
  ?assertEqual(?MESSAGE, ecies:private_decrypt(PrivateKey, Data, Params)).

aead_check(Cipher, MacBits) ->
  Params = #{ cipher => Cipher, mac => {aead, MacBits} },
  {PublicKey, PrivateKey} = ecies:generate_key(),
  Data = ecies:public_encrypt(PublicKey, ?MESSAGE, Params),
  ?assertEqual(?MESSAGE, ecies:private_decrypt(PrivateKey, Data, Params)).

% See: IEEE Std 1609.2a™-2017 - ECIES Test Vector 1
ecies_aes_ccm_128_bit_key_wrap_test() ->
  Params  = #{
    curve => secp256r1,
    cipher => 'xor',
    kdf => {kdf, sha256},
    mac => {hmac, sha256, 128},
    key => { binary:decode_hex(<<"03F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828">>), % sender's ephemeral public key
             binary:decode_hex(<<"1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42">>) },  % sender's ephemeral private key
    s1 => binary:decode_hex(<<"A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9">>) % recipient info
  },
  
  KeyToWrap  = binary:decode_hex(<<"9169155B08B07674CBADF75FB46A7B0D">>),
  
  PublicKey  = binary:decode_hex(<<"028C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB11">>), % recipient's public key
  PrivateKey = binary:decode_hex(<<"060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085">>),   % recipient`s private key

  Data = ecies:public_encrypt(PublicKey, KeyToWrap, Params),
  ?assertEqual(KeyToWrap, ecies:private_decrypt(PrivateKey, Data, Params)),
  
  Expected = binary:decode_hex(<<
    "03F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828" % sender's ephemeral public key
    "A6342013D623AD6C5F6882469673AE33" % encrypted (wrapped) AES key
    "80e1d85d30f1bae4ecf1a534a89a0786" % authentication tag
  >>),
  ?assertEqual(Expected, Data).
