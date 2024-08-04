%% @doc
%% This module provides specific params defaults and overrides compatible with Electrum, Electron Cash, ElectrumSV
%% and BitcoinSV ECIES implementation.
%%
-module(ecies_electrum).

-export([default_params/0, params/1]).

%% @doc Default params compatible with electrum BIE1 ECIES implementation.
%%
%% Using `secp256k1' elliptic curve, HMAC SHA-256 with 256 bits output authentication tag using
%% AES-128 CBC encryption and BIE1 message encapsulation.
%% Additionally it provides callback for electrum specific keys and IV derivation function, and proper
%% cipher data encoding.
-spec default_params() -> ecies:ecies_params().
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

%% @doc Utility function for overriding default electrum compatible params
%% @equiv maps:merge(default_params(), Params)
params(Params) ->
  maps:merge(default_params(), Params).

% electrum specific overrides
-spec shared_key(ecies:ecies_params()) -> {ok, ecies:ecies_params()}.
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