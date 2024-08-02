-module(ecies_electrum).

-export([default_params/0, params/1]).

default_params() ->
  #{
    curve => secp256k1,
    cipher => aes_128_cbc,
    mac => {hmac, sha256, 256},
    shared_key  => fun shared_key/1,
    derive_keys => fun derive_keys/1,
    prepare_payload => fun prepare_payload/1,
    encode => fun encode/1,
    decode => fun decode/1
  }.

params(Params) ->
  maps:merge(default_params(), Params).

% electrum specific overrides
shared_key(#{ others_public_key := OthersPublicKey, key := {_PublicKey, PrivateKey} } = State) ->
  % electrum is using modified ECDH with full (but compresses) public key as output, instead of just x coordinate
  SharedKey = ecies_pubkey:compress(ecies_pubkey:mul(OthersPublicKey, PrivateKey, State), default_params()),
  {ok, State#{ shared_key => SharedKey }}.

derive_keys(#{ shared_key := SharedKey } =  State) ->
  % non standard key derivation with iv derivation instead of using standard 0000..00 or iv embedded in payload
  <<IV:16/bytes, EncKey:16/bytes, MacKey:32/bytes>> = crypto:hash(sha512, SharedKey),
  {ok, State#{ iv => IV, enc_key => EncKey, mac_key => MacKey }}.

prepare_payload(#{ key := {PublicKey, _PrivateKey}, cipher_text := CipherText } = State) ->
  {ok, State#{ payload => <<"BIE1", PublicKey/binary, CipherText/binary>> }}.

encode(#{ payload := Payload, mac := MAC }) ->
  base64:encode(<<Payload/binary, MAC/binary>>).

decode(#{ cipher_data := CipherData, mac_length := MacLen } = State) ->
  MessageWithMAC = base64:decode(CipherData),
  MessageLen = byte_size(MessageWithMAC) - MacLen,
  <<Message:MessageLen/bytes, MAC:MacLen/bytes>> = MessageWithMAC,
  CipherTextLen = byte_size(Message) - 4 - 33,
  <<"BIE1", OthersPublicKey:33/bytes, CipherText:CipherTextLen/bytes>> = Message,
  {ok, State#{ payload => Message, expected_mac => MAC, cipher_text => CipherText, others_public_key => OthersPublicKey }}.