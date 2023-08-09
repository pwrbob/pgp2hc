# `pgp2hc`: PGP to hashcat

This program extracts [hashcat](https://hashcat.net/hashcat/) and [John the Ripper](https://www.openwall.com/john/) hashes from encrypted secret keys in the OpenPGP format.
In particular, it supports newer ECC key types.

## Overview

This program was designed to be compatible with the output of `gpg2john` for all key types that it supports,
while allowing treatment of newer elliptic curves keys.
This implementation is in Rust and bases on the [`pgp`](https://docs.rs/pgp) crate,
which already parses all types and greatly simplifies the code.

## Examples

**hashcat format:**
```bash
pgp2hc keyfile.sec  # we can omit the default "--format hashcat"
```
output:
```
$gpg$*18*54*264*2eefdaf289960ef8b02977e653caf2776e031139762c4a346f13606449cffb2bb531760d2c1f9982dadec5e0521074fd38739225eb6e*3*254*2*7*16*1a1d80158008a96949dd9d26bdb0f9c7*65011712*0154f0be62105c3d
```

**John format:**
```bash
pgp2hc keyfile.sec --format john
```
output: (including the spurious newline to stderr at the beginning for exact compatibility)
```

File keyfile.sec
BobBob:$gpg$*18*54*264*2eefdaf289960ef8b02977e653caf2776e031139762c4a346f13606449cffb2bb531760d2c1f9982dadec5e0521074fd38739225eb6e*3*254*2*7*16*1a1d80158008a96949dd9d26bdb0f9c7*65011712*0154f0be62105c3d:::BobBob::keyfile.sec
```

## Testing

Test cases require the `john` and `john-samples` repositories to be available, with the `john` binary and `gpg2john` symlink being available.
This can be achieved by cloning both repositories, and building john as described there.
You should specify the paths to the roots of the repositories in the following environment variables, for example in a `.env` file:

- `JOHN_PATH=/path/to/john`  (without the `/run/` directory)
- `JOHN_SAMPLES_PATH=/path/to/john-samples`

This allows comparing the output of `gpg2john` with the output of `pgp2hc --format john`,
to ensure it does the same thing.

The latest version of John for which this was tested is commit [c798c3f](https://github.com/openwall/john/commit/c798c3f39215f6e08c67677eb9b79f65cfe08e40).

## FAQ

- Why not `gpg2hc` instead of `pgp2hc`?

The file format is OpenPGP ([RFC 4880](https://www.rfc-editor.org/rfc/rfc4880.html)), GPG is simply one program that uses this format.
