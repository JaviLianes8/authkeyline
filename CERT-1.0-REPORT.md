# authkeyline 1.0.0 certification report

The 1.0.0 certification bar applied to authkeyline. PyPI has no release of the name
(`https://pypi.org/pypi/authkeyline/json` answered 404 on 2026-10-18), so 1.0.0 is the
first published version; changes are listed against 0.2.0, the state of `main` at 220dd19.

Progress:
- [x] Branch `release/1.0.0` created from `main` (220dd19, version 0.2.0, never on PyPI)
- [ ] Baseline gates on 0.2.0
- [ ] Ground truth: OpenSSH sources and test data fetched again, ssh-keygen and OpenSSH itself run as oracles (item 7)
- [ ] API review and 1.0.0 changes (item 1)
- [ ] Errors, typing, docstrings and doctests (items 2 to 5)
- [ ] Contract, fuzz and author mutation round (items 6, 9, 18)
- [ ] Docs: README, GUIDE, CHANGELOG (items 11, 12)
- [ ] Packaging, e2e and every Python (items 8, 10, 13, 14)
- [ ] Gates (item 15)
- [ ] Five QA lenses (item 19) and independent reviewer (item 16)
- [ ] PR and trace guard (item 17); merge and publish left to the maintainer
