# Vendored PCRE2 header

`pcre2.h` is copied unchanged from the `pcre2-sys` 0.2.9 crate
(`upstream/include/pcre2.h`, PCRE2 10.43, BSD-3-Clause, notice kept in the
file). The library itself is compiled and linked by `pcre2-sys`; this header
only lets `mitm_anixops.c` see the same declarations.

Keep it in step with the `pcre2-sys` version pinned in `../../Cargo.toml`:
when that pin moves, copy the new crate's `upstream/include/pcre2.h` here.
