# authkeyline 1.0.0 author mutation table

The author mutation round of [CERT-1.0-REPORT.md](https://github.com/JaviLianes8/authkeyline/blob/main/CERT-1.0-REPORT.md).
Each mutant was applied alone to a fresh clone of `release/1.0.0` at d5950d9 on another
machine (CPython 3.14, fetched sources and `ssh-keygen` present, no sshd oracle there),
and the whole suite, doctests included, ran with `-x` and a 300 s per-test limit. The
first failing test is listed; a test id cut at its first blank is shown without its
parameter. All 38 were killed.

M01 to M32 were first run at bcbbf78, where M11 and M15 survived until the contracts of
`tests/test_contract_edges.py` (ba24013) were added. They were run again at d5950d9 after
the QA fixes, M22 rewritten for the status held in a list, and M33 to M38 added for the
code those fixes brought (the key type rule, the plain `hash` copy, Windows name escaping,
the closed reader check and the unreadable file status).

| Mutant | Module | Change | Killed by |
| --- | --- | --- | --- |
| M01 | `_optrules.py` | expiry seconds capped at 60 | `test_options.py::test_expiry_time_accepts_the_sshd_formats[20301231235961z]` |
| M02 | `_optrules.py` | tunnel maximum off by one | `test_options.py::test_tunnel_rejects_others[2147483646]` |
| M03 | `_optrules.py` | bare permitlisten port not widened | `test_options.py::test_permitlisten_also_takes_a_bare_port[8080]` |
| M04 | `_optrules.py` | port and tunnel lower bound exclusive | `__init__.py::authkeyline.AuthorizedKey.values (doctest)` |
| M05 | `_options.py` | backslash escapes any character | `test_build.py::test_quotes_are_escaped_and_backslashes_kept` |
| M06 | `_options.py` | repeated command allowed | `test_build.py::test_duplicate_single_options_are_refused` |
| M07 | `_model.py` | last environment value wins | `__init__.py::authkeyline.AuthorizedKey.environment (doctest)` |
| M08 | `_wire.py` | negative mpint accepted | `test_blob.py::test_rsa_size_floor_and_integer_rules` |
| M09 | `_blob.py` | RSA floor off by one | `test_blob.py::test_rsa_size_floor_and_integer_rules` |
| M10 | `_blob.py` | spare base64 bits accepted | `test_oracle.py::test_both_skip_spare_base64_bits_and_keep_odd_comments` |
| M11 | `_curves.py` | x equal to p accepted | `test_contract_edges.py::test_coordinates_must_be_below_the_prime[nistp256]` |
| M12 | `_keycheck.py` | curve and cert ignored in type check | `test_certificates.py::test_certificate_line_type_must_match_its_blob` |
| M13 | `_records.py` | SHA256 fingerprint keeps padding | `__init__.py::authkeyline.AuthorizedKey.fingerprint (doctest)` |
| M14 | `_codec.py` | NUL does not end the line | `test_parse.py::test_malformed_lines_raise` |
| M15 | `_codec.py` | comment loses inner-edge whitespace kinds | `test_contract_edges.py::test_the_comment_starts_after_spaces_and_tabs_only[\x0b]` |
| M16 | `_build.py` | quotes in values not escaped | `test_build.py::test_quotes_are_escaped_and_backslashes_kept` |
| M17 | `_build.py` | single trailing backslash written | `test_build.py::test_options_that_could_inject_or_would_not_read_back` |
| M18 | `_cert.py` | one principal too many accepted | `test_certificates.py::test_principal_limit` |
| M19 | `_cert.py` | certificate types swapped | `__init__.py::authkeyline.Certificate (doctest)` |
| M20 | `_wire.py` | NUL before the last byte accepted | `test_blob.py::test_type_name_with_a_nul_is_refused` |
| M21 | `_errors.py` | messages quote long values | `test_fuzz.py::test_damaged_blobs_raise_only_auth_key_errors[7]` |
| M22 | `_cli.py` | broken lines exit 0 | `test_cli.py::test_broken_lines_go_to_stderr_and_exit_1` |
| M23 | `_keytypes.py` | rsa-sha2-512 dropped | `__init__.py::authkeyline (doctest)` |
| M24 | `_optrules.py` | UTC epoch expiry accepted | `test_review_fixes.py::test_expiry_at_the_epoch_is_refused[19700101Z]` |
| M25 | `_options.py` | trailing comma accepted | `test_authopt.py::test_upstream_rejected_fields_raise` |
| M26 | `_wire.py` | u64 read little-endian | `__init__.py::authkeyline.Certificate (doctest)` |
| M27 | `_model.py` | has_flag case-sensitive | `__init__.py::authkeyline.AuthorizedKey (doctest)` |
| M28 | `_optrules.py` | dash allowed in environment names | `test_options.py::test_environment_rejects_other_names[A-B=1]` |
| M29 | `_codec.py` | comment lines counted as entries | `__init__.py::authkeyline.AuthKeyError (doctest)` |
| M30 | `_records.py` | MD5 bytes not zero padded | `__init__.py::authkeyline.PublicKey.fingerprint (doctest)` |
| M31 | `_blob.py` | security key application left out of the fingerprint | `test_oracle.py::test_listing_matches_ssh_keygen` |
| M32 | `_build.py` | no read-back check | `test_build.py::test_options_that_could_inject_or_would_not_read_back` |
| M33 | `_codec.py` | unknown key type reported as an unknown option | `test_parse.py::test_malformed_lines_raise` |
| M34 | `_codec.py` | quoted or comma options word taken as a key type | `test_qa_round6.py::test_an_unknown_option_is_still_named_as_an_option` |
| M35 | `_records.py` | str subclass steers the md5 choice | `test_qa_round6.py::test_fingerprint_compares_a_plain_copy_of_the_hash[public]` |
| M36 | `_streams.py` | windows name surrogates U+DC80..U+DCFF written as bytes | `test_qa_round5.py::test_a_windows_name_has_every_surrogate_escaped[\udc80]` |
| M37 | `_streams.py` | disk full swallowed as a gone reader | `test_qa_round4_writer.py::test_an_output_error_that_is_not_a_closed_reader_is_raised[28]` |
| M38 | `_cli.py` | unreadable file exits 1 | `test_qa_cli_round2.py::test_an_unreadable_file_then_a_broken_one_exits_2` |
