# APIMapper Lite

A single-user, offline workbench for reviewing API contracts and previously captured HTTP traffic. A project keeps an inventory, contract differences, manually labeled authorization contexts, workflow steps and review questions in SQLite. Importing a URL never contacts its host. ARTEX, an LLM, a GPU and a container runtime are unnecessary.

## Start locally

Use Python 3.11 or newer on Windows or Linux. The measured configuration used CPython 3.14.5 on Windows. Run these commands from the folder containing this README.

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8765
```

**Linux**

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8765
```

Open [the local dashboard](http://127.0.0.1:8765). Stop with Ctrl+C. Use one server process. Package installation needs a package index or a prepared local wheel directory. For a disconnected install, supply matching wheels for the target OS and Python version, including transitive dependencies, and pass `--no-index --find-links PATH` to pip. The running app serves its own CSS and needs only loopback.

## Try the included evidence

1. Create a project. Import [archive.openapi.json](examples/archive.openapi.json) as **OpenAPI JSON**, followed by [archive.har](examples/archive.har) as **HAR 1.2**. Expect three documented operations and five observed requests. Reimporting the same content with identical format and origin preserves the original records and labels.
2. Load [approved-scope.json](examples/approved-scope.json) under **Approved scope**, give the fixture policy a reference and check the review box. The fixture excludes `/v1/health`. Missing or ambiguous scope stays unknown. An unknown endpoint never establishes authorization.
3. Open **Endpoint explorer**. Follow the first two HAR evidence links and assign aliases A and B, roles Owner and Reader, tenants North and South, authentication states Signed in and Anonymous, and ownership Own and Shared. The matrix groups their recorded 200 and 403 under `GET /v1/reports/{id}`. The literal `/v1/reports/me` remains separate. Each request retains its own evidence link.
4. Open **Spec comparison**. The second capture references `/log/entries/1/request`. Its extra query name, missing required query name, 403 response and missing bearer metadata can each be traced to the definition and capture. A sanitized recording or older contract can explain a difference.
5. Create a workflow called Receipt approval. Add a Submit step with Owner, Draft → Submitted, and the first capture. Add a Close step with Approved → Closed and leave the expected role blank. **Hypothesis review** shows the gap between the two states and the missing role. Save a research status, contrary evidence and a note.
6. Under **Export**, download `API_ENDPOINTS.md`, `API_AUTHORIZATION_MATRIX.md`, `API_ATTACK_SURFACES.md`, `API_HYPOTHESES.md`, `API_WORKFLOWS.md` and `api-inventory.json`. The JSON v1 bundle joins records by ID and carries filenames, source hashes, pointers, timestamps, labels and triage. These are ordinary files for manual transfer to another tool.

## Accepted inputs

| Format | Evidence the app retains | Coverage limits |
| --- | --- | --- |
| HAR 1.2 | Recorded method, origin, path, query and header names, authentication metadata, status and JSON field types | Encoded bodies are omitted with a warning. Response shapes sample four array elements and bounded nesting. |
| OpenAPI 3.0.x / 3.1.x, JSON or YAML | Specified operations, servers, parameters, security alternatives and response declarations | Whole-segment path variables, local JSON Pointer references, basic properties/items. Relative root servers need an operator-supplied origin. External or cyclic references produce warnings. Complex schema composition and callbacks are outside the comparison. |
| Postman Collection v2.1 | Collection requests and compatible saved response examples | Uses collection variables. Skips unresolved URLs and mismatched saved requests with a warning. Scripts never run. These records do not populate the observed authorization matrix. [Fixture](examples/archive.postman.json) |
| Raw HTTP text pair | One request and one matching response, with independent names, hashes and location references | Upload both UTF-8 files. For a relative target enter the exact capture origin, such as `https://api.example.invalid`. The supplied Host must agree. [Request](examples/request.http) · [Response](examples/response.http) |
| Scope JSON v1 | Operator-approved policy reference, SHA-256 and exact-origin literal path prefixes | Include and exclude rules match path segment boundaries. Exclusions take precedence. Policy inputs use literal prefixes. No matching rule yields unknown. |

Native ARTEX traffic JSON is unsupported pending a verified, versioned export schema. The app can read a supported standard artifact produced elsewhere. It exposes no remote engine operations.

An observation's `kind` identifies its source of authority. Only observed traffic contributes outcomes. Matching compares scheme, host, effective port, method and case-sensitive path. More-specific literal paths take precedence. Equally specific competing templates and duplicate contracts produce explicit comparison entries. Records on unrelated origins stay separate. The comparisons cover query names, required header and cookie presence, status codes, declared authentication evidence, methods and field-name sensitivity. They cannot establish policy compliance or a vulnerability.

## Data handling and operating limits

The database defaults to `%LOCALAPPDATA%\apimapper-lite\inventory.sqlite3` on Windows and `$XDG_DATA_HOME/apimapper-lite/inventory.sqlite3` (or `~/.local/share/apimapper-lite/inventory.sqlite3`) on Linux. Set `APIMAPPER_DATA` before launch to choose a private local directory. Stop the server before copying its whole data directory for backup; restore by selecting the copied directory. A project export is a portable review artifact, while the database backup preserves private matching keys.

The database stores selected metadata. Request body values, response body values, header values and query values are discarded. Unrecognized captured path segments become project-specific keyed identifiers. Schema and header names, hostnames, literal paths declared by a specification, filenames, scope rules and researcher notes are meaningful evidence and can themselves be sensitive. Use aliases, review files before sharing, and protect the local user account. Multipart handling may temporarily spool larger uploads in the OS temp directory. The operator keeps the original files separately when exact reproduction is needed. The app never stores a permanent raw copy.

| Setting | Default | Effect |
| --- | ---: | --- |
| `APIMAPPER_FILE_MIB` | 2 | Per uploaded artifact, configurable from 1 to 16 MiB |
| `APIMAPPER_SECONDS` | 12 | Per parser subprocess, configurable from 1 to 90 seconds |
| `APIMAPPER_MEMORY_MIB` | 192 | Parser process memory ceiling, configurable from 64 to 512 MiB |
| `APIMAPPER_RECORDS` | 1,000 | Records per import and project, configurable from 1 to 4,000 |

One artifact import runs at a time. The parser enforces a Windows Job Object or Linux address-space limit and refuses input if the limiter fails. Uploads also have fixed request-length checks. A project is limited to 8 MiB of stored normalized observation data and 120 sources. Scope uploads have a separate 128 KiB HTTP request limit. Choose another project for a separate corpus. The 512 MiB–1 GiB host target includes interpreter, database, temporary files and OS overhead; the parser ceiling alone is not a whole-host reservation.

## Verification

For tests install `httpx==0.28.1` into the same environment. The optional measurement script also uses `psutil==7.2.2`. Neither is a direct application requirement. With that environment's Python, run:

```sh
python -m unittest discover -s tests -v
python tools/measure.py --entries 250
```

The [acceptance tests](tests/test_workflow.py) use real uploads, SQLite and parser subprocesses. The [measurement](tools/measure.py) launches Uvicorn on a temporary loopback port, imports a 250-entry synthetic HAR and three definitions, renders the research views, exports JSON, saves a role and verifies it in a new interpreter after shutdown. It samples server and parser RSS together; the HTTP client, browser and OS are excluded. Repeating fixture shapes measures the normal review path. Highly diverse paths, deep schemas and near-limit inputs need separate measurements on the deployment machine.

**Recorded run · 19 November 2026.** Windows, CPython 3.14.5, server affinity restricted to two logical CPUs. The seven acceptance tests passed in 1.754 seconds. They exercised all five input choices, raw credential omission, duplicate imports, malformed and oversized inputs, cross-project access checks, route ambiguity, the allocation limit, all eight hypothesis categories, manual triage, all dashboard views and six exports.

| Local benchmark, 250 captures and 3 definitions | Observed |
| --- | ---: |
| Idle server RSS | 58.6 MiB |
| Maximum sampled server + parser RSS, 16 samples | 77.0 MiB |
| Uploads, review views, JSON export and label save | 0.45 s |
| SQLite file after shutdown | 332 KiB |
| Saved role present after reopening the database | Yes |

The sampled peak can miss brief spikes. This run used Windows only and did not impose a 512 MiB limit on the entire machine.

Format references: [OpenAPI specification](https://spec.openapis.org/oas/v3.1.1.html) · [Postman v2.1 collection schema](https://schema.postman.com/collection/json/v2.1.0/draft-07/docs/index.html) · [HAR 1.2](https://www.softwareishard.com/blog/har-12-spec/).
