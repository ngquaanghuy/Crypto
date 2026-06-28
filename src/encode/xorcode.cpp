/* xorcode.cpp — umbrella compilation unit
 * All XOR cipher implementations have been split into:
 *   xor_basic.cpp     — basic XOR, authenticated XOR, rolling XOR, bit rotation
 *   xor_protect.cpp   — protect wrappers (PBKDF2 key derivation + HMAC) + multi-pass XOR
 *   xor_prng.cpp      — PRNG-XOR (ChaCha20-based) + protect wrappers
 *
 * Public API remains in include/crypto/xorcode.h — no changes for callers.
 */
