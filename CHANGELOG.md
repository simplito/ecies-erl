# Changelog

All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2024-08-04

Functions provided by `m:ecies_electrum` module depends no longer on `libsecp256k1` 
and are working now without any additional dependecies.
We also provide functions for standard encoding/decoding of keys in [PEM] format.

### Added

- `m:ecies_pem` module with utility functions to encode/decode public/private/keypair to [PEM] format.
- `m:ecies_pubkey` module with functions for compressing, decompressing public key and deriving public key 
   from the given private one

### Removed

- `ecies_electrum:is_supported/0` as it is no longer needed

## [1.0.0] - 2024-08-01

Initial release

[PEM]: https://datatracker.ietf.org/doc/html/rfc7468

[Unreleased]: https://github.com/simplito/ecies-erl/compare/v1.1.0...develop
[1.1.0]: https://github.com/simplito/ecies-erl/compare/tag/v1.0.0...v1.1.0
[1.0.0]: https://github.com/simplito/ecies-erl/releases/tag/v1.0.0
