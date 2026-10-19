# authkeyline 1.0.0 author mutation table

The author mutation round of [CERT-1.0-REPORT.md](https://github.com/JaviLianes8/authkeyline/blob/main/CERT-1.0-REPORT.md).
Each mutant was applied alone to a fresh clone of `release/1.0.0` at bcbbf78 on another
machine (CPython 3.14, fetched sources and `ssh-keygen` present, no sshd oracle there),
and the whole suite, doctests included, ran with `-x` and a 300 s per-test limit. The
first failing test is listed. M11 and M15 survived that round; the contracts of
`tests/test_contract_edges.py` (ba24013) were added and both mutants were run again and
killed.

| Mutant | Module | Change | Killed by |
| --- | --- | --- | --- |
| M01 | `_optrules.py` | expiry-time seconds capped at 60 | `test_options.py::test_expiry_time_accepts_the_sshd_formats[20301231235961z]` |
| M02 | `_optrules.py` | tunnel maximum off by one | `test_options.py::test_tunnel_rejects_others[2147483646]` |
| M03 | `_optrules.py` | bare permitlisten port not widened to `*:port` | `test_options.py::test_permitlisten_also_takes_a_bare_port[8080]` |
| M04 | `_optrules.py` | port and tunnel lower bound exclusive | `_model.py::authkeyline._model.AuthorizedKey.values` (doctest) |
| M05 | `_options.py` | a backslash escapes any character | `test_build.py::test_quotes_are_escaped_and_backslashes_kept` |
| M06 | `_options.py` | a repeated `command` allowed | `test_build.py::test_duplicate_single_options_are_refused` |
| M07 | `_model.py` | the last environment value wins | `_model.py::authkeyline._model.AuthorizedKey.environment` (doctest) |
| M08 | `_wire.py` | negative mpint accepted | `test_blob.py::test_rsa_size_floor_and_integer_rules` |
| M09 | `_blob.py` | RSA floor 1023 bits | `test_blob.py::test_rsa_size_floor_and_integer_rules` |
| M10 | `_blob.py` | set spare base64 bits accepted | `test_oracle.py::test_both_skip_spare_base64_bits_and_keep_odd_comments` |
| M11 | `_curves.py` | x equal to p accepted | round 2: `test_contract_edges.py::test_coordinates_must_be_below_the_prime[nistp256]` |
| M12 | `_keycheck.py` | curve and certificate ignored in the type check | `test_certificates.py::test_certificate_line_type_must_match_its_blob` |
| M13 | `_records.py` | SHA256 fingerprint keeps its padding | `_model.py::authkeyline._model.AuthorizedKey.fingerprint` (doctest) |
| M14 | `_codec.py` | a NUL does not end the line | `test_oracle.py::test_both_skip_spare_base64_bits_and_keep_odd_comments` |
| M15 | `_codec.py` | every kind of whitespace trimmed from the comment start | round 2: `test_contract_edges.py::test_the_comment_starts_after_spaces_and_tabs_only[\x0b]` |
| M16 | `_build.py` | quotes in values not escaped | `test_build.py::test_quotes_are_escaped_and_backslashes_kept` |
| M17 | `_build.py` | a single trailing backslash written | `test_build.py::test_options_that_could_inject_or_would_not_read_back[option6]` |
| M18 | `_cert.py` | one principal over the limit accepted | `test_certificates.py::test_principal_limit` |
| M19 | `_cert.py` | user and host certificate types swapped | `_records.py::authkeyline._records.Certificate` (doctest) |
| M20 | `_wire.py` | a NUL before the last byte of a text field accepted | `test_blob.py::test_type_name_with_a_nul_is_refused` |
| M21 | `_errors.py` | messages quote 4000 characters | `test_fuzz.py::test_damaged_blobs_raise_only_auth_key_errors[7]` |
| M22 | `_cli.py` | broken lines exit 0 | `test_cli.py::test_broken_lines_go_to_stderr_and_exit_1` |
| M23 | `_keytypes.py` | `rsa-sha2-512` dropped from the table | `__init__.py::authkeyline` (doctest) |
| M24 | `_optrules.py` | the UTC epoch accepted as expiry | `test_review_fixes.py::test_expiry_at_the_epoch_is_refused[19700101Z]` |
| M25 | `_options.py` | a trailing comma accepted | `test_authopt.py::test_upstream_rejected_fields_raise` |
| M26 | `_wire.py` | u64 read little-endian | `_records.py::authkeyline._records.Certificate` (doctest) |
| M27 | `_model.py` | `has_flag` case-sensitive | `_model.py::authkeyline._model.AuthorizedKey` (doctest) |
| M28 | `_optrules.py` | `-` allowed in environment names | `test_options.py::test_environment_rejects_other_names[A-B=1]` |
| M29 | `_codec.py` | `#` comment lines counted as entries | `_codec.py::authkeyline._codec.parse_file` (doctest) |
| M30 | `_records.py` | MD5 bytes not zero padded | `_records.py::authkeyline._records.PublicKey.fingerprint` (doctest) |
| M31 | `_blob.py` | security key application left out of the fingerprint | `test_oracle.py::test_listing_matches_ssh_keygen` |
| M32 | `_build.py` | no read-back check in `build_line` | `test_build.py::test_options_that_could_inject_or_would_not_read_back[option10]` |
