# MISP galaxy clusters (subset, trimmed)

Nine cluster files from the MISP galaxy project, one per malware category: `ransomware`,
`stealer`, `rat`, `botnet`, `banker`, `backdoor`, `tool`, `exploit-kit`, `cryptominers`.

- Source: https://github.com/MISP/misp-galaxy (`clusters/<name>.json`)
- Commit: `24877de22e9614057e59b1096ab8bf5fc3d8c395` (2026-10-29)
- Downloaded: 2026-10-29

Licence: CC0 1.0, or the 2-clause BSD licence (dual-licensed; `LICENSE.md` in this
directory, copied from the same commit). The files carry no per-file licence field.

## Modification

The committed files are **not** byte copies. Each is `cti.reference.trim_misp_cluster()`
applied to the upstream file. It keeps the cluster header and, per family, `value`, `uuid`,
`description`, `related`, `meta.synonyms` and `meta.refs`, minus links to Tor hidden services.
It drops everything else, notably ransom notes (one holds a victim's negotiation-portal login),
leak-site links, prices, payment methods and suspected victims. This project publishes no
victim data and no live .onion URLs, and a family → category lookup needs none of it.
Committed SHA-256s are in `cti.reference.PINNED`. The upstream SHA-256s were:

| File | Upstream SHA-256 |
|---|---|
| `ransomware.json` | `5bb087baaef2f595a632f40667e8a3ad0199cb1a542ea2d82a31ad1382bdaa71` |
| `stealer.json` | `1dfeba2bfbcde3382befc2215b3df33c40101f7c874751e2564210f0250bdbef` |
| `rat.json` | `5f940cc05ee07154d5161ee4763ca798c822a335342b82d5c00fe9dc9884877c` |
| `botnet.json` | `ba1b6e2407cf465c82bdd3b617d35ed8af519dabd36b684d2d9b11d2e34bc8b3` |
| `banker.json` | `1f6bd1dcf26af8d3b54bfb430081486a902f471e57a18666d5aef79e433437c0` |
| `backdoor.json` | `71c741e70e776764902e01383a5ee0f13e151c808e6df1590c0fd018d87d28a4` |
| `tool.json` | `ea45a13ea589b553f88ddaf51fd17dda8f8db38712774aeb98f893374688bae4` |
| `exploit-kit.json` | `9c12a13195ccbd426c83bd04590d41260534c87677a01b04ea4ea44e8144b88a` |
| `cryptominers.json` | `4510ddcc802c082732c057db53e9fc34292cc9f7d880c580a8c7c8c4c47844f3` |

Used in Phase 10a as one source of family → category labels (category = the cluster
file). `malpedia.json` is deliberately not included: Malpedia data is CC BY-NC-SA and has
no category field.
