-module(ecies_kdf).

-export([hkdf/5, hkdf_extract/3, hkdf_expand/4]).
-export([kdf/4, concat_kdf/4]).

% HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
% https://datatracker.ietf.org/doc/html/rfc5869
% https://datatracker.ietf.org/doc/html/rfc8418#section-2.2
-spec hkdf(Hash, Key, Salt, Info, Length) -> Result
    when
      Hash :: atom(),
      Key  :: binary(),
      Salt :: binary(),
      Info :: binary(),
      Length :: pos_integer(),
      Result :: binary().
hkdf(Hash, Key, Salt, Info, Length) ->
  PRK = hkdf_extract(Hash, Key, Salt),
  hkdf_expand(Hash, PRK, Info, Length).

-spec hkdf_extract(Hash, Salt, IKM) -> Result
    when
      Hash :: atom(),
      Salt :: binary(),
      IKM  :: binary(),
      Result :: binary().
hkdf_extract(Hash, <<>>, IKM) ->
    #{ size := HashSize } = crypto:hash_info(Hash),
    Salt = <<0:HashSize/unit:8>>,
    hkdf_extract(Hash, Salt, IKM);
hkdf_extract(Hash, Salt, IKM) ->
    crypto:mac(hmac, Hash, Salt, IKM).

-spec hkdf_expand(Hash, PRK, Info, Length) -> Result
    when
      Hash :: atom(),
      PRK  :: binary(),
      Info :: binary(),
      Length :: pos_integer(),
      Result :: binary().
hkdf_expand(Hash, PRK, Info, Length) ->
    #{ size := HashSize } = crypto:hash_info(Hash),
    N = ceil(Length / HashSize),
    Bin0 = lists:foldl(
        fun(I, Acc) ->
            [crypto:mac(hmac, Hash, PRK, <<(hd(Acc))/binary, Info/binary, I>>) | Acc]
        end, [<<>>], lists:seq(1, N)),
    Bin1 = tl(lists:reverse(Bin0)),
    Bin2 = iolist_to_binary(Bin1),
    binary:part(Bin2, 0, Length).

% The ANSI-X9.63-KDF key derivation function.
% https://datatracker.ietf.org/doc/html/rfc8418#section-2.1
-spec kdf(Hash, Key, Info, Length) -> Result
    when
      Hash :: atom(),
      Key  :: binary(),
      Info :: binary(),
      Length :: pos_integer(),
      Result :: binary().
kdf(Hash, Key, Info, Length) ->
    #{ size := HashSize } = crypto:hash_info(Hash),
    N = ceil(Length / HashSize),
    Bin0 = lists:map(fun(I) -> crypto:hash(Hash, <<Key/binary, I:32, Info/binary>>) end, lists:seq(1, N)),
    Bin1 = iolist_to_binary(Bin0),
    binary:part(Bin1, 0, Length).

% NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
-spec concat_kdf(Hash, Key, Info, Length) -> Result
  when
  Hash :: atom(),
  Key  :: binary(),
  Info :: binary(),
  Length :: pos_integer(),
  Result :: binary().
concat_kdf(Hash, Key, Info, Length) ->
  kdf(Hash, Info, Key, Length).