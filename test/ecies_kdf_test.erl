-module(ecies_kdf_test).

-include_lib("eunit/include/eunit.hrl").

-define(h2b(S), binary:decode_hex(list_to_binary(S))).
-define(b2h(S), binary_to_list(binary:encode_hex(S, lowercase))).

% https://datatracker.ietf.org/doc/html/rfc5869#appendix-A

hkdf_case_1_test() ->
  % Basic test case with SHA-256

  Hash = sha256,
  IKM  = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", % (22 octets)
  Salt = "000102030405060708090a0b0c", % (13 octets)
  Info = "f0f1f2f3f4f5f6f7f8f9", % (10 octets)
  L    = 42,

  PRK  = "077709362c2e32df0ddc3f0dc47bba63"
         "90b6c73bb50f9c3122ec844ad7c2b3e5", % (32 octets)
  OKM  = "3cb25f25faacd57a90434f64d0362f2a"
         "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
         "34007208d5b887185865", % (42 octets)

  ?assertEqual(PRK, ?b2h(ecies_kdf:hkdf_extract(Hash, ?h2b(Salt), ?h2b(IKM)))),
  ?assertEqual(OKM, ?b2h(ecies_kdf:hkdf_expand(Hash, ?h2b(PRK), ?h2b(Info), L))).


hkdf_case_2_test() ->
  % Test with SHA-256 and longer inputs/outputs

  Hash = sha256,
  IKM  = "000102030405060708090a0b0c0d0e0f"
         "101112131415161718191a1b1c1d1e1f"
         "202122232425262728292a2b2c2d2e2f"
         "303132333435363738393a3b3c3d3e3f"
         "404142434445464748494a4b4c4d4e4f", % (80 octets)
  Salt = "606162636465666768696a6b6c6d6e6f"
         "707172737475767778797a7b7c7d7e7f"
         "808182838485868788898a8b8c8d8e8f"
         "909192939495969798999a9b9c9d9e9f"
         "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", % (80 octets)
  Info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
         "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
         "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
         "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", % (80 octets)
  L    = 82,

  PRK  = "06a6b88c5853361a06104c9ceb35b45c"
         "ef760014904671014a193f40c15fc244", % (32 octets)
  OKM  = "b11e398dc80327a1c8e7f78c596a4934"
         "4f012eda2d4efad8a050cc4c19afa97c"
         "59045a99cac7827271cb41c65e590e09"
         "da3275600c2f09b8367793a9aca3db71"
         "cc30c58179ec3e87c14c01d5c1f3434f"
         "1d87", % (82 octets)

  ?assertEqual(PRK, ?b2h(ecies_kdf:hkdf_extract(Hash, ?h2b(Salt), ?h2b(IKM)))),
  ?assertEqual(OKM, ?b2h(ecies_kdf:hkdf_expand(Hash, ?h2b(PRK), ?h2b(Info), L))).


hkdf_case_3_test() ->
  % Test with SHA-256 and zero-length salt/info

  Hash = sha256,
  IKM  = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", % (22 octets)
  Salt = "", % (0 octets)
  Info = "", % (0 octets)
  L    = 42,

  PRK  = "19ef24a32c717b167f33a91d6f648bdf"
         "96596776afdb6377ac434c1c293ccb04", % (32 octets)
  OKM  = "8da4e775a563c18f715f802a063c5a31"
         "b8a11f5c5ee1879ec3454e5f3c738d2d"
         "9d201395faa4b61a96c8", % (42 octets)

  ?assertEqual(PRK, ?b2h(ecies_kdf:hkdf_extract(Hash, ?h2b(Salt), ?h2b(IKM)))),
  ?assertEqual(OKM, ?b2h(ecies_kdf:hkdf_expand(Hash, ?h2b(PRK), ?h2b(Info), L))).

hkdf_case_4_test() ->
  % Basic test case with SHA-1

  Hash = sha, % SHA-1
  IKM  = "0b0b0b0b0b0b0b0b0b0b0b", % (11 octets)
  Salt = "000102030405060708090a0b0c", % (13 octets)
  Info = "f0f1f2f3f4f5f6f7f8f9", % (10 octets)
  L    = 42,

  PRK  = "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243", % (20 octets)
  OKM  = "085a01ea1b10f36933068b56efa5ad81"
         "a4f14b822f5b091568a9cdd4f155fda2"
         "c22e422478d305f3f896", % (42 octets)

  ?assertEqual(PRK, ?b2h(ecies_kdf:hkdf_extract(Hash, ?h2b(Salt), ?h2b(IKM)))),
  ?assertEqual(OKM, ?b2h(ecies_kdf:hkdf_expand(Hash, ?h2b(PRK), ?h2b(Info), L))).

hkdf_case_5_test() ->
  % Test with SHA-1 and longer inputs/outputs

  Hash = sha, % SHA-1
  IKM  = "000102030405060708090a0b0c0d0e0f"
         "101112131415161718191a1b1c1d1e1f"
         "202122232425262728292a2b2c2d2e2f"
         "303132333435363738393a3b3c3d3e3f"
         "404142434445464748494a4b4c4d4e4f", % (80 octets)
  Salt = "606162636465666768696a6b6c6d6e6f"
         "707172737475767778797a7b7c7d7e7f"
         "808182838485868788898a8b8c8d8e8f"
         "909192939495969798999a9b9c9d9e9f"
         "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", % (80 octets)
  Info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
         "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
         "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
         "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", % (80 octets)
  L    = 82,

  PRK  = "8adae09a2a307059478d309b26c4115a224cfaf6", % (20 octets)
  OKM  = "0bd770a74d1160f7c9f12cd5912a06eb"
         "ff6adcae899d92191fe4305673ba2ffe"
         "8fa3f1a4e5ad79f3f334b3b202b2173c"
         "486ea37ce3d397ed034c7f9dfeb15c5e"
         "927336d0441f4c4300e2cff0d0900b52"
         "d3b4", % (82 octets)

  ?assertEqual(PRK, ?b2h(ecies_kdf:hkdf_extract(Hash, ?h2b(Salt), ?h2b(IKM)))),
  ?assertEqual(OKM, ?b2h(ecies_kdf:hkdf_expand(Hash, ?h2b(PRK), ?h2b(Info), L))).

hkdf_case_6_test() ->
  % Test with SHA-1 and zero-length salt/info

  Hash = sha, % SHA-1
  IKM  = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", % (22 octets)
  Salt = "", % (0 octets)
  Info = "", % (0 octets)
  L    = 42,

  PRK  = "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01", % (20 octets)
  OKM  = "0ac1af7002b3d761d1e55298da9d0506"
         "b9ae52057220a306e07b6b87e8df21d0"
         "ea00033de03984d34918", % (42 octets)

  ?assertEqual(PRK, ?b2h(ecies_kdf:hkdf_extract(Hash, ?h2b(Salt), ?h2b(IKM)))),
  ?assertEqual(OKM, ?b2h(ecies_kdf:hkdf_expand(Hash, ?h2b(PRK), ?h2b(Info), L))).

hkdf_case_7_test() ->
  % Test with SHA-1, salt not provided (defaults to HashLen zero octets),
  % zero-length info

  Hash = sha, % SHA-1
  IKM  = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", % (22 octets)
  Salt = "", % not provided (defaults to HashLen zero octets)
  Info = "", % (0 octets)
  L    = 42,

  PRK  = "2adccada18779e7c2077ad2eb19d3f3e731385dd", % (20 octets)
  OKM  = "2c91117204d745f3500d636a62f64f0a"
         "b3bae548aa53d423b0d1f27ebba6f5e5"
         "673a081d70cce7acfc48", % (42 octets)

  ?assertEqual(PRK, ?b2h(ecies_kdf:hkdf_extract(Hash, ?h2b(Salt), ?h2b(IKM)))),
  ?assertEqual(OKM, ?b2h(ecies_kdf:hkdf_expand(Hash, ?h2b(PRK), ?h2b(Info), L))).

%%%%%%%%%%%%%%5

kdf_case_1_test() ->
  Hash = sha256,
  IKM  = "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08",
  Info = "",
  L    = 16,

  OKM = "443024c3dae66b95e6f5670601558f71",

  ?assertEqual(OKM, ?b2h(ecies_kdf:kdf(Hash, ?h2b(IKM), ?h2b(Info), L))).

kdf_case_2_test() ->
  Hash = sha256,
  IKM  = "96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4",
  Info = "",
  L    = 16,

  OKM = "b6295162a7804f5667ba9070f82fa522",

  ?assertEqual(OKM, ?b2h(ecies_kdf:kdf(Hash, ?h2b(IKM), ?h2b(Info), L))).

kdf_case_3_test() ->
  Hash = sha256,
  IKM  = "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d",
  Info = "75eef81aa3041e33b80971203d2c0c52",
  L    = 128,
  
  OKM  = "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21",
  
  ?assertEqual(OKM, ?b2h(ecies_kdf:kdf(Hash, ?h2b(IKM), ?h2b(Info), L))).

kdf_case_4_test() ->
  Hash = sha256,
  
  IKM  = "7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a",
  Info = "d65a4812733f8cdbcdfb4b2f4c191d87",
  L    = 128,
  
  OKM  = "c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b",
  
  ?assertEqual(OKM, ?b2h(ecies_kdf:kdf(Hash, ?h2b(IKM), ?h2b(Info), L))).
