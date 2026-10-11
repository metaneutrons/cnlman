# cnlman

Click'n'Load for the command line. cnlman receives the packages a link
protector hands to "JDownloader", decrypts them and prints the links as JSON,
optionally passing them straight to [pyLoad](https://pyload.net/).

It is built for scripts and AI agents: no GUI, JSON on stdout, diagnostics on
stderr, and distinct exit codes for "nothing arrived" and "nothing found".

> **Status:** early development, no release yet.

## Installation

The repository is private. With access:

```bash
cargo install --locked --git ssh://git@github.com/metaneutrons/cnlman.git
```

## Two ways to get a package

**Listen**, the way JDownloader does it. Start the listener, then press the
Click'n'Load button on the page:

```bash
cnlman listen --once --timeout 300
```

**Extract** the payload from the page source instead. A protector page already
contains everything the button would send, for example filecrypt's
`CNLPOP('<id>', '<hex key>', '<crypted>', '<package>')` or hidden `jk` and
`crypted` form inputs. No port, no click, no race:

```bash
cnlman extract page.html
curl -s … | cnlman extract
```

Extraction depends on the page markup. When a site assembles the payload in
script, use the listener.

Both print one line per package:

```json
{"origin":"cnlpop","name":"My.Package","links":["https://host.example/file1","https://host.example/file2"]}
```

| Field | Meaning |
| --- | --- |
| `origin` | `addcrypted2` or `add` (listener), `cnlpop` or `form` (extract), `manual` (decrypt) |
| `name` | package name sent by the page, if any |
| `passwords` | archive passwords sent by the page, if any |
| `source` | the page the package came from, if known |
| `links` | the decrypted links |
| `pyload_package_id` | present when the package was added to pyLoad |

`--format links` prints the bare links instead, one per line.

## Commands

| Command | Purpose |
| --- | --- |
| `cnlman listen` | serve `127.0.0.1:9666` (`--bind`, `CNLMAN_BIND`); `--once`, `--count N`, `--timeout SECONDS` |
| `cnlman extract [FILE]` | decode payloads in saved HTML; stdin when no file or `-` |
| `cnlman decrypt --jk … --crypted …` | decrypt one pair; `--crypted -` reads stdin |
| `cnlman push --name NAME [FILE]` | add links (one per line) to pyLoad |

The listener answers `/jdcheck.js`, `/crossdomain.xml`, `/flash/addcrypted2`
and `/flash/add`. DLC containers (`/flash/addcrypted`) are not supported.

## pyLoad

Add `--pyload` to `listen`, `extract` or `decrypt` to hand every package to
pyLoad as it is decoded.

```bash
export PYLOAD_URL=http://nas.local:8000
export PYLOAD_API_KEY=pl_…        # pyLoad → Settings → API
cnlman listen --once --pyload
```

pyLoad 0.5 and later authenticate with an API key (`X-API-Key`). The key is
read only from the environment, never from the command line, and it is sent
only over HTTPS or to a host on the local network; `--pyload-insecure`
overrides that. `--pyload-dest collector` parks packages in the link collector
instead of the queue.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | error (bad payload, port in use, pyLoad rejected the request, …) |
| 2 | `listen` timed out before any package arrived |
| 3 | `extract` found no Click'n'Load payload in the page |

## Agent workflow

1. Open the container page in a browser and solve the captcha. That step is
   for a human.
2. Either save the page source and run `cnlman extract`, or start
   `cnlman listen --once --timeout 300` in the background and press the
   Click'n'Load button.
3. Read the JSON line, or let `--pyload` hand the links over directly.

## Security

Click'n'Load lets any page open in the browser post to the listener. cnlman
therefore binds to loopback only, refuses other addresses without
`--allow-remote`, and is meant to run briefly (`--once`, `--timeout`) rather
than as a permanent service.

## License

[GPL-3.0-or-later](LICENSE)
