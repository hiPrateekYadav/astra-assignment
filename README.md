# vulnscan

A frontier model scans a decompiled Android app, turns its findings into general lessons, and teaches
a smaller open model. The pipeline then measures how much the open model's recall improves.

Status: ingest, scanning, lessons, rescan and measurement all work end to end. Results, the match
function rationale and the dynamic-analysis design are in [docs/writeup.md](docs/writeup.md).

## Setup

### With Docker (recommended)

Works the same on macOS, Linux and Windows, on Intel or ARM. You need Docker with Compose 2.24 or
newer, and no local Python or Java.

    cp .env.example .env    # then add your API keys
    cp /path/to/target.apk apps/
    docker compose build
    docker compose run --rm vulnscan check-models
    docker compose run --rm vulnscan --app /apps/target.apk ingest --digest
    docker compose run --rm vulnscan --app /apps/target.apk scan --role teacher

`config/` and `data/` are mounted from this folder, so config edits apply straight away and reports
appear in `data/runs/`. Rerun `docker compose build` after changing `src/`.

- **Memory:** jadx uses up to 70% of the container's memory. For large APKs, give Docker Desktop at
  least 6 GB. If jadx is killed the run stops with an error rather than scanning partial output.
- **Linux, if `id -u` is not 1000:** add `HOST_UID` and `HOST_GID` to `.env` with your values, so the
  container can write to `data/`.

### Without Docker

You need Python 3.12 or newer. Java and `jadx` are needed only to decompile an `.apk`.

    pip install -e ".[dev]"
    cp .env.example .env    # then add your API keys
    vulnscan check-models   # add --list to see every model each provider offers
    vulnscan ingest --digest    # show what would be scanned
    pytest

In VS Code, "Reopen in Container" gives you this setup with everything installed.

### Choosing an app

Put the APK in `apps/` and pass it with `--app`. It is decompiled automatically with jadx; the output
is cached in `data/runs/decompiled/`, so it is decompiled only once:

    vulnscan --app apps/your-app.apk loop --repeat 3

Without a ground-truth file, the student is scored against the teacher's findings. The default app,
models and thresholds are set in `config/config.yaml`. `--app` also takes an already decompiled
directory (jadx's default output or its Gradle export).

## What ingest produces

- First-party code only. App packages are inferred from the manifest, and bundled libraries and
  generated files are skipped using lists in config.
- Decompiler noise removed, with original line numbers kept for reporting locations.
- A manifest digest to attach to every scan chunk, because whether code is reachable depends on
  how its component is declared.
- App-owned strings, `res/xml` configs and small text assets as scan units.
- A library and version inventory, as library code is not scanned but its versions still matter.

## Scanning

    vulnscan scan --role teacher
    vulnscan scan --role student --repeat 3

Each model reports typed findings from `config/taxonomy.yaml`, with a location, severity and evidence.
Reports are written to `data/runs/<package>/`.

- Every evidence quote is looked up in the named file, ignoring only layout and case. Findings that
  fail are dropped and kept in the report for audit.
- Validated responses are cached, so rerunning after a quota error pays only for unfinished chunks.
- A rate limit with a long wait stops the scan. The report is marked as stopped and is not scored;
  rerunning resumes it from the cache.
- Code over `scan.max_total_tokens` is skipped in risk order, and up to `scan.max_failed_chunk_ratio`
  of chunks may fail. Those runs are still scored, with a warning, because rerunning would not change
  them.
- If the manifest digest is over `scan.max_digest_tokens`, each chunk gets only the manifest entries
  for its own code, so a large manifest cannot use up a tight rate limit.

Free tiers shape the defaults: Gemini allows about 20 requests a day per model, so the teacher sends
large chunks, and Groq allows 8,000 tokens a minute, so the student sends small ones. Chunk size is set
per role with `max_chunk_tokens`.

## The learning loop

    vulnscan --ground-truth data/ground_truth/insecureshop.yaml loop --repeat 3

This runs a teacher scan, N student baselines, one teacher call that turns its findings into
general lessons, N student rescans with those lessons, and then the evaluation. Each step also runs
on its own: `scan --role student --lessons data/runs/<package>/lessons-<student-model>.json`, `lessons` and
`evaluate`. Results go to `data/runs/<package>/results-<student-model>.md` and `.json`, or
`results-vs-teacher-<student-model>.*` when there is no ground truth.

To add runs to a finished experiment, reuse its lessons rather than running `loop` again, because more
baseline runs change the lesson prompt and produce a different set of lessons:

    vulnscan scan --role student --repeat 5
    vulnscan scan --role student --repeat 5 --lessons data/runs/<package>/lessons-<student-model>.json
    vulnscan --ground-truth labels.yaml evaluate

If rescans from different lesson sets are on disk, only the newest set is scored and the rest are
listed in a warning.

- **Lessons** come from the teacher's own findings, each marked with whether the student's baseline
  caught it. The ground truth is never shown to a model. Any lesson that names the app's classes,
  package, resource keys, quoted literals, file names or line numbers is rejected, and kept in
  the lessons file for audit. Report and result files are named by model, so switching a
  role's model never mixes runs.
- **Matching** a finding to a ground-truth entry needs the right file, an accepted type, and an
  anchor token at the reported code. Pairing is one-to-one, so duplicates cannot inflate recall.
  Without a ground truth (`app.ground_truth: null`), the teacher's findings are the reference. The
  thresholds are under `match` in config.
- **Variance:** temperature 0 is not deterministic, so recall is reported as a mean and range over
  `--repeat` runs. The evaluation warns when the lift is within that spread, when a report is
  unfinished or partial, or when the student starts flagging much more.

### Scoring with your own labels

Pass `--ground-truth labels.yaml`, using `data/ground_truth/insecureshop.yaml` as the example:

    entries:
      - id: 1
        title: WebView loads attacker URL
        files: [com/acme/WebActivity.java]   # where it may be reported; a path suffix is enough
        types: [webview_url_loading]         # accepted IDs from config/taxonomy.yaml
        anchors: [loadUrl]                   # optional code tokens; leave out to match on file and type

The path in `files` is the logical one: `com/acme/Foo.java`, `AndroidManifest.xml` or
`res/values/strings.xml`.

## Adding a model

- New model on a configured provider (`gemini`, `groq`, `openai`, `anthropic`): change `provider` and
  `model` under `roles`, and add that provider's key to `.env`. For example, to teach with Claude:

      teacher:
        provider: anthropic
        model: claude-sonnet-5-5
        max_output_tokens: 32768
        max_chunk_tokens: 12000
        extra_params:    # optional: another model answers if a safety classifier declines a chunk
          betas: [server-side-fallback-2026-07-01]
          fallbacks: default

  For OpenAI models that reject `temperature`, set `temperature: null`.
- New OpenAI-compatible provider: add an entry under `providers` and name its key in `.env`.
- New wire format: add one file in `src/vulnscan/models/` that subclasses `ModelClient`, implements
  `_send`, uses `@register_adapter("name")`, and is imported in `models/__init__.py`. Then set
  `adapter: name` in config. `models/anthropic_messages.py` is a working example.
