# Minimal JSON fixture set (`updateJSONLite`)

**TESTING ONLY. This is not a substitute for the real definitions.**

This directory mirrors the layout of the JSON structures that MISP normally ingests from its
submodules under `app/files/`, but contains only the handful of entries the test suites actually
depend on. It is read exclusively by `cake Admin updateJSONLite`
(`Server::updateJSON(true)`); `cake Admin updateJSON` never looks at it and keeps reading the
full corpus from the submodules.

Unlike the submodule-backed corpus, this directory is committed to the MISP repository, so
`updateJSONLite` also works on a checkout made **without** `--recursive`.

## Contents and why each entry is here

| Path | Kept because |
|---|---|
| `misp-galaxy/{galaxies,clusters}/mitre-mobile-attack-attack-pattern.json` | `PyMISP/tests/testlive_comprehensive.py` looks up the galaxy named `Mobile Attack - Attack Pattern` |
| `misp-galaxy/{galaxies,clusters}/wiper.json` | Sorts last alphabetically, so it is the highest-id galaxy that `galaxies()[0]` returns; it has clusters (needed by `test_galaxy_cluster`, `test_event_galaxy`, `tests/testlive_sync.py`) and its name `Wiper` matches no other retained galaxy, which `test_search_galaxy` requires |
| `warninglists/lists/public-dns-v4`, `public-dns-v6`, `public-dns-hostname` | Exactly three lists must match `%dns resolv%` (`'3 warninglist(s) enabled'`). The two large ones are trimmed to a few entries, keeping `8.8.8.8`, `9.9.9.9` and `1.1.1.1`, and deliberately **not** `8.8.8.9` or `1.11.71.4`, which must trip nothing |
| `warninglists/lists/common-ioc-false-positive` | Looked up by name, and must contain the empty-file MD5 `d41d8cd98f00b204e9800998ecf8427e` |
| `taxonomies/tlp` | Looked up by namespace; its `red` predicate materialises the `tlp:red` tag that `tests/testlive_comprehensive_local.py` searches for |
| `misp-objects/objects/{file,domain-ip,asn}` | Required by name by the live suites |
| `misp-objects/relationships/definition.json` | Verbatim; ingestion is cheap and nothing is gained by trimming it |
| `noticelists/lists/gdpr` | Looked up by name |

Every file except the two trimmed warninglists is a verbatim copy of its upstream submodule
counterpart. The trimmed ones have their `version` lowered to `1` so that a subsequent real
`updateJSON` on the same database always supersedes them.

## Extending this set

If a test starts depending on another galaxy, warninglist, taxonomy, object template or
noticelist, copy that entry here from the corresponding submodule, keeping the same filename and
directory layout. Watch out for the count-based assertions listed above: adding a warninglist
whose name contains `dns resolv`, or a galaxy that sorts after `wiper.json`, will break them.
