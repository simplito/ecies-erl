[![Build and Test](https://github.com/simplito/ecies-erl/actions/workflows/erlang.yml/badge.svg)](https://github.com/simplito/ecies-erl/actions/workflows/erlang.yml)
[![Hex](https://img.shields.io/hexpm/v/ecies.svg)](https://hex.pm/packages/ecies)

Customizable Erlang native ECIES public-key cryptography library
================================================================

An Erlang native library implementing the ECIES (Elliptic Curve Integrated Encryption Scheme) public-key cryptography, providing elliptic curve encryption as an alternative to the deprecated `crypto` `public_encrypt`, `private_decrypt` functions.

Motivation
----------

The Erlang OTP team decided to deprecate several `crypto` module functions in OTP 27 (See [functions deprecated in OTP 27](https://www.erlang.org/doc/deprecations.html#functions-deprecated-in-otp-27)).
Notably, no alternatives were provided for two of them `crypto:public_encrypt/4` and `crypto:private_decrypt/4`.

Some information about potential background of these deprecations can be found [here](https://erlangforums.com/t/security-working-group-minutes/3451/6).

It is worth mentioning that the above mentioned functions are RSA specific and cannot be used with Elliptic Curve cryptography anyway. 
In our projects we mainly use Elliptic Curve cryptography and we decided to share this small library for ECIES with the Erlang developers community.  

We will be happy if you find it useful and use in your project. If you find any ideas for improvements or notice any missing functionality, please open an issue here; even better propose a Pull Request.

Usage
-----

The API of library is simple:
- `ecies:generate_key/0`- can be used to generate public/private key pair
- `ecies:public_encrypt/2` - for encrypting binary message with given public key
- `ecies:private_decrypt/2` - for decrypting data using private key corresponding to public key used in `public_encrypt`

Example: 

```erlang
% Bob generates keys, and publish his public key
{BobPublicKey, BobPrivateKey} = ecies:generate_key(),
% Alice knowing Bob's public key encrypts a message for him
Data = ecies:public_encrypt(BobPublicKey, <<"top secret message">>),
% Bob is able to decrypt the message using his private key
<<"top secret message">> = ecies:private_decrypt(BobPrivateKey, Data).
```

In the above example the default params are used (as returned by `ecies:default_params/0`):
```erlang
  #{
    curve    => secp256k1,
    cipher   => aes_256_cbc,
    kdf      => {kdf, sha256},      % ANSI-X9.63 key derivation
    mac      => {hmac, sha256, 256} % HMAC SHA256 with 256 bits (32 bytes) output
  }.
```

### Customisation

Using `ecies:generate_key/1`, `ecies:public_encrypt/3`, `ecies:private_decrypt/3` functions which accepts extra `Params` argument you can customize elliptic curve and algorithms used in all steps of encryption/decryption process.

There are a few library API functions that helps with customisation:
- `ecies:default_params/0` - returns default set of params
- `ecies:supports/1`- which can be used to inspect lists of all supported curves, ciphers, hashs (digest types)

We also provide default params compatible with existing ECIES variants used in some other libraries.

- `ecies_bitcore:default_params/0` - compatible with [bitcore](https://github.com/bitpay/bitcore-ecies/) ECIES implementation
- `ecies_geth:default_params/0`, `ecies_geth:params_from_curve/1` - compatible with [ethereum's geth](https://github.com/ethereum/go-ethereum) ECIES implementation
- `ecies_electrum:default_params/0` - compatible with [Electrum](https://github.com/spesmilo/electrum), [Electron Cash](https://github.com/Electron-Cash/Electron-Cash) and [ElectrumSV](https://github.com/electrumsv/electrumsv) ECIES implementation (see also [here](https://github.com/gitzhou/bitcoin-ecies))

> [!NOTE]
> Electrum related functions requires [libsecp256k1](https://hex.pm/packages/libsecp256k1) dependency in your project. We also provide function `ecies_electrum:is_supported/0`[^1] 

Example 1:
```erlang
% Alice and Bob agrees on the following params
Params = #{
  curve  => x25519,         % Edwards curve 25519
  kdf    => {hkdf, sha256}, % HMAC-based Extract-and-Expand KDF with SHA256 hash
  cipher => aes_256_ctr,
  mac    => {hmac, sha256, 96} % HMAC with SHA256 and 96 bits output
},
  % Bob generates keys
{BobPublicKey, BobPrivateKey} = ecies:generate_key(Params),
% Alice knowing Bob's public key encrypts a message for him
Data = ecies:public_encrypt(BobPublicKey, <<"top secret message">>, Params),
% Bob is able to decrypt the message using his private key
<<"top secret message">> = ecies:private_decrypt(BobPrivateKey, Data, Params).
```
Example 2:
```erlang
% Decrypting electrum compatible message
Params = ecies_electrum:default_params(),
PrivateKey = binary:decode_hex(<<"ee3231b5deea48b619814d72a6e1aa04a9f521df281afad5ada89f5393941b1c">>),
MessageBase64 = <<"QklFMQJdmY+9Ys1WjqANreLwXaau62N01r9lebJ9Rp7Az+XRMdNAVgg3J8EEVhni5gn2v+WOD59uDMDp0zY/xPT3IElReQo6XUCSMmgRgRtYl+TUEw==">>,
<<"hello world">> = ecies:private_decrypt(PrivateKey, MessageBase64, Params).
```

---

The list of all supported elliptic curves (`curve` param), ciphers (`cipher` param) and hash functions used by KDF and MAC 
algorithms can be obtained using `ecies:supports/1` function:

```erlang
-spec supports(hashs)  -> [digest_type()];
              (curves) -> [named_curve()];
              (ciphers) -> [cipher()];
              (cmac_ciphers) -> [cmac_cipher()];
              (aead_ciphers) -> [aead_cipher()].
```

> [!NOTE]
> For Edwards Curves 25519 and 448 use `x25519`, `x448`, and not `ed25519`, `ed448`

For key derivation (`kdf` param) you can use:
```erlang
-type kdf_type() :: {hkdf, digest_type()} | % HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
                    {kdf, digest_type()}  | % ANSI-X9.63 KDF
                    {concat_kdf, digest_type()}  | % NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
                    kdf_fun().
% Custom KDF function
-type kdf_fun()  :: fun((SharedKey :: binary(), Info :: binary(), Length :: pos_integer()) -> Result :: binary()).
```

For message authentication (`mac` param):
```erlang
-type mac_type()    :: {hmac, digest_type(), mac_bits()} | % HMAC for given digest function with specified output bits
                       {cmac, cmac_cipher(), mac_bits()} | % CMAC with AES-*-CBC cipher and given output bits
                       {aead, mac_bits()}. % Special case when AES CCM/GCM ciphers are used to just specify tag output bits 
-type mac_bits()    :: pos_integer() | default. % default atom means output size equal to given mac key length
```

License
-------
`ecies` library is MIT-licensed, as per [LICENSE.md](LICENSE.md).

[^1]: Unfortunately Electrum uses full compressed point from Diffie-Hellman step of calculating shared key 
instead of usual x coordinate, and erlang's `crypto:compute_key` is not enough to calculate this. 
