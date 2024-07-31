![Build and Test](https://github.com/simplito/ecies-erl/actions/workflows/erlang.yml/badge.svg)
[![Hex](https://img.shields.io/hexpm/v/ecies.svg)](https://hex.pm/packages/ecies)

Customizable Erlang native ECIES public-key cryptography library
================================================================

An Erlang native library implementing the ECIES (Elliptic Curve Integrated Encryption Scheme) public-key cryptography.  
It allows for configurable components such as DH key agreement, key derivation, data encryption, MAC algorithms and more.

Examples tailored to ECIES variants implemented in Electrum, Geth, and Bitcore are also provided.

Motivation
----------

The Erlang OTP team decided to deprecate several `crypto` module functions in OTP 27 (See [functions deprecated in OTP 27](https://www.erlang.org/doc/deprecations.html#functions-deprecated-in-otp-27))  
Notably, no alternatives were provided for two of them `crypto:public_encrypt/4`, `crypto:private_decrypt/4`.   
It is worth mentioning that the above mentioned functions are RSA specific and cannot be used with Elliptic Curve cryptography anyway. 

Some information about potential background of these deprecations can be found [here](https://erlangforums.com/t/security-working-group-minutes/3451/6).

In our projects we mainly use Elliptic Curve cryptography and we decided to share this small library for ECIES with the Erlang developers community.  
We will be happy if you find it useful and use in your project. If you find any ideas for improvements or notice any missing functionality, please open an issue here; even better propose a Pull Request.

Usage
-----

### Basic

The simplest variant without additionals params:

```erlang
  % Bob generates keys
  {BobPublicKey, BobPrivateKey} = ecies:generate_key(),
  % Alice knowing Bob's public key encrypts a message for him
  Data = ecies:public_encrypt(BobPublicKey, <<"top secret message">>),
  % Bob is able to decrypt the message using his private key
  <<"top secret message">> = ecies:private_decrypt(BobPrivateKey, Data).
```

In that case the default params are used (as returned by `ecies:default_params/0`):
```erlang
  #{
    curve    => secp256k1,
    cipher   => aes_256_cbc,
    kdf      => {kdf, sha256},      % ANSI-X9.63 key derivation
    mac      => {hmac, sha256, 256} % HMAC SHA256 with 256 bits (32 bytes) output
  }.
```

### Customisation

Specifying additional argument `Params` to the `generate_key`, `public_encrypt` and `privated_decrypt` function you can
customize algorithms used in all steps of encryption / decryption.

Example:
```erlang
  % Alice and Bob agrees on the following params
  Params = #{ curve => x25519, kdf => {hkdf, sha256}, cipher => aes_256_ctr, mac => {hmac, sha256, 96} },
  % Bob generates keys
  {BobPublicKey, BobPrivateKey} = ecies:generate_key(Params),
  % Alice knowing Bob's public key encrypts a message for him
  Data = ecies:public_encrypt(BobPublicKey, <<"top secret message">>, Params),
  % Bob is able to decrypt the message using his private key
  <<"top secret message">> = ecies:private_decrypt(BobPrivateKey, Data, Params).
```

The list of all supported elliptic curves (`curve` param), ciphers (`cipher` param) and hash functions used by KDF and MAC 
algorithms can be obtained using `ecies:supports/1` function:

```erlang
-spec supports(hashs)  -> [digest_type()];
              (curves) -> [named_curve()];
              (ciphers) -> [cipher()];
              (cmac_ciphers) -> [cmac_cipher()];
              (aead_ciphers) -> [aead_cipher()].
```
NOTE: For Edwards Curves 25519 and 448 do use `x25519` and `x448`.

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

Additionally we provide default params used in bitcore[^1], geth[^2], electrum[^3].

Example usage:
```erlang
  Params = ecies_electrum:default_params(),
  PrivateKey = binary:decode_hex(<<"ee3231b5deea48b619814d72a6e1aa04a9f521df281afad5ada89f5393941b1c">>),
  MessageBase64 = <<"QklFMQJdmY+9Ys1WjqANreLwXaau62N01r9lebJ9Rp7Az+XRMdNAVgg3J8EEVhni5gn2v+WOD59uDMDp0zY/xPT3IElReQo6XUCSMmgRgRtYl+TUEw==">>,
  <<"hello world">> = ecies:private_decrypt(PrivateKey, MessageBase64, Params).
```
NOTE: Unfortunately Electrum uses full compressed point from Diffie-Hellman step of calculating shared key instead
of usual x coordinate, and erlang's `crypto:compute_key` is not enough to calculate this. For using electrum compatible
params you need to add `libsecp256k1` to your dependencies, otherwise `error(unsupported)` will be thrown.

More advanced usage cases will be described later.

[^1]: https://github.com/bitpay/bitcore-ecies
[^2]: https://github.com/ethereum/go-ethereum/blob/master/crypto/ecies/ecies.go
