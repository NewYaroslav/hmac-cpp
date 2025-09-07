# Changelog

## [Unreleased]

## [0.5.0] - 2025-09-07
### Added
- Lifecycle management APIs and hardened zeroing for `secure_buffer`.
- Improved `secret_string` implementation for better safety and performance.
- Expanded tests covering nonce rotation and integrity checks in `secret_string`.

### Changed
- Renamed `secret.hpp` to `secret_string.hpp`; includes must update.

### Notes
- Breaking changes: header rename.

## [0.4.0] - 2025-09-06
### Added
- Base32 (RFC 4648), Base64, and Base36 encoding/decoding utilities.
- `secure_buffer<T>` zeroizing container and helpers (page locking, secret_string).
- Expanded HOTP/TOTP test coverage.

### Changed
- CMake install exports new headers.
- README updated.

### Notes
- Breaking changes: none (public API only extended).

## [0.3.0] - 2025-09-05
### Added
- PBKDF2 implementation.

### Fixed
- Documentation corrections.

