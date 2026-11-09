# vulnscan: teacher-to-student vulnerability scanning

## Results

InsecureShop, scored against its 19 known vulnerabilities. Full table: `docs/results/RESULTS.md`.

| | Model | Recall (average) | Range |
|---|---|---|---|
| Teacher | gemini-3-flash-preview | **78.9%** (15/19) | 1 run |
| Student before lessons | openai/gpt-oss-120b | **49.1%** | 47–53% (3 runs) |
| Student after 14 lessons | openai/gpt-oss-120b | **66.7%** | 63–68% (3 runs) |

**Lift: +17.5 points.** The share of findings that match a known bug did not drop: it went from 53% to 59%. Findings per run went from 17.7 to 21.3.

- **Gained:** #4 code execution (1/3 → 3/3), #5 intent redirection (1/3 → 3/3), #15 content provider (1/3 → 3/3), #12 implicit broadcast (0/3 → 2/3), #7 file theft (1/3 → 2/3), #9 broadcast receiver (0/3 → 1/3), #11 FileProvider paths (2/3 → 3/3).
- **Lost:** #2 URL validation (1/3 → 0/3).
- **Never found:** #3, #8, #13 and #14. The teacher missed them too, so lessons drawn from the teacher's findings can't teach them. 15/19 is the ceiling for this method.
- **How much to trust it:** every lesson run (12–13 of 19) beat every baseline run (9–10 of 19), so the lift is larger than the spread between identical runs. With 3 runs per side that ordering is 1 of 20 possible, about p = 0.05 one-sided, so it is a good signal, not proof. It is also one app, and the lessons were written from this app's code.
- **An earlier experiment was smaller:** 2 runs per side with 15 lessons gave 52.6% → 63.2% (+10.5), which was within that experiment's 21-point spread. I report the later run because it has more repeats and its raw reports are in the repo, but the gap between the two is a fair measure of how noisy this is.
- **All 14 lessons passed** the generality check, with 0 rejected. An earlier version of the check wrongly rejected general lessons containing plain words like "webview". That was fixed before this run.

**The lift holds under different match settings** (raw reports in `docs/results/insecureshop/`):

| Match setting | Teacher | Before | After | Lift |
|---|---|---|---|---|
| Default (anchor within 8 lines of the evidence) | 15/19 | 49.1% | 66.7% | +17.5 |
| Strict (anchor in the quoted evidence only) | 14/19 | 49.1% | 63.2% | +14.0 |
| No anchors (file and type only) | 15/19 | 54.4% | 66.7% | +12.3 |
| Against the teacher's 21 findings, no labels | - | 41.3% | 58.7% | +17.5 |

## Pipeline

1. **Ingest.** jadx decompiles the APK, or a decompiled directory is loaded. First-party packages are inferred from the manifest, and library and generated code is skipped using lists in config. Decompiler noise is removed but original line numbers are kept. The scan units are the code, the manifest, app strings, `res/xml` and small assets, plus a library inventory. Every chunk carries a manifest digest, because whether code is reachable depends on how its component is declared.
2. **Scan.** Each model returns typed findings with a type, file, line, severity, evidence and rationale, using a closed 21-type taxonomy (`config/taxonomy.yaml`). Every evidence quote is looked up in the named file. Quotes that can't be found are dropped and kept for audit, which removes invented code before anything is scored. Responses are cached, so a run that hits a quota resumes where it stopped.
3. **Lessons.** The teacher sees its own verified findings, each marked with whether the student's baseline caught it, and writes general rules in one call. It never sees the ground truth. A code check then rejects any lesson that names the app's classes, first-party package, string-resource keys or quoted literals, or that mentions a `.java` file or a line number. Rejected lessons are kept in the lessons file for audit.
4. **Rescan and measure.** The student rescans with the lessons in its system prompt, which is the only difference from the baseline prompt (a unit test checks this). Both sides run N times, and recall is reported as the mean and range over those runs.

## Match function

A finding counts as a hit on a ground-truth entry only if **all three** of these hold:

1. **File:** its resolved file is one the entry lists. A suffix match is allowed.
2. **Type:** its type is one of the entry's accepted taxonomy IDs.
3. **Anchor:** one of the entry's anchor tokens appears at the reported code. That means in the verified evidence, or within ±8 lines (`anchor_window_lines`) of the line where the scanner located that evidence.

Findings and entries are then paired **one-to-one** by maximum bipartite matching. One finding can't claim two entries, and ten duplicate findings count once.

Why this design:

- **Deterministic and explainable, not an LLM judge.** A judge model drifts between runs, can be persuaded by confident rationales, and would add its own noise to a lift that is already small. Every hit here can be traced to a file, a type and a token.
- **Files and types catch the right location and class of bug.** Several types per entry (e.g. a FileProvider issue is `arbitrary_file_access`, and an exported-service CVE may be `vulnerable_dependency` or `exported_component_exposure`) absorb honest taxonomy disagreement without fuzzy type similarity.
- **Anchors separate issues that share a file and type.** InsecureShop has two `webview_url_loading` bugs in one activity: a missing path check and a weak `endsWith` host check. Anchors also stop a generic finding in a busy file from claiming a specific bug. "Some exported activity in the manifest" must not count as "an exported third-party service with a known CVE".
- **Anchors are checked at the code, not in the quote alone.** My first version searched only the evidence string. On the baselines that rewarded the student for pasting 5-line blocks and penalised the teacher for quoting the one line that mattered (`openInputStream(fileUri)` four lines below `Uri.fromFile`). The surrounding lines come from the app, not the model, and only when the evidence was verified, so they can't be gamed. **This change was made after looking at the baseline scans and before any lesson run.** The Results section also reports the strict setting (`anchor_window_lines: 0`, evidence only), where the lift is +14.0 instead of +17.5.
- **Titles and rationales are never searched.** They are free text a model can fill with keywords.
- **Unmatched findings are "unlabelled", not false positives.** The README list isn't exhaustive. The teacher correctly reports `debuggable=true`, `allowBackup`, cleartext traffic and more that aren't among the 19. So "matched share" is a lower bound on precision, and I watch it only for big swings.

**Without a ground truth** (an unseen APK with `app.ground_truth: null`), the teacher's findings become the reference. A student finding matches a teacher finding on the same file and type, within `line_window` lines or with overlapping quoted code, using the same one-to-one pairing. This measures how close the student gets to the teacher, not true recall. It inherits every teacher miss and every teacher false positive.

**Limits.**
- The anchors and accepted types are hand annotations of one app. I wrote them before any scan and froze them with a SHA-256 that the loader checks, but they are still my judgement.
- 19 items means one entry is about 5 points of recall. A lift of one or two entries is within what a different annotator might score differently.
- One app cannot show that the lessons generalise. The teacher was shown findings on the same code the student is then scored on. Even if every lesson is general in wording, the lessons were chosen to cover this app's bugs. The honest test is held out: see below.

### How I'd test generalisation (held out)

- **Cross-app.** Generate lessons on app A, rescan app B with them, and compare against B's baseline. Use several deliberately vulnerable apps (InsecureShop, DIVA, InjuredAndroid, OVAA, AndroGoat) and rotate which ones lessons come from.
- **Leave one type out.** Drop every teacher finding of type T before generating lessons, then measure the lift on T. Any lift on T then comes from transfer, not instruction.
- **A placebo control.** A same-length block of generic Android security advice that isn't derived from teacher findings. That separates "the lessons taught something" from "a longer, more security-heavy prompt makes the model flag more".

## Scaling to 1M+ lines of code

The current design sends every first-party file. That's fine for 3k lines and wrong for 1M. What I'd change:

1. **Triage by reachability before any model sees code.** Build the attack surface from the manifest (exported components, deep-link filters, providers) and the code (registered receivers, JavaScript bridges, network clients). Then build a call graph with a cheap static tool (Soot/FlowDroid, or jadx's own index) and keep only methods reachable from an entry point. A taint pass finds source-to-sink paths, such as intent extras reaching `loadUrl`, `startActivity`, `rawQuery` or file APIs. Most of a large app is UI and business logic that never touches attacker input.
2. **Chunk by slice, not by file.** For each candidate path, send the entry point, the methods along the path and the sink, plus the manifest entry. This is the unit a model can reason about. A 3,000-line activity split blindly across chunks loses the data flow that matters.
3. **Tier the models.** The cheap student scans every slice. The teacher sees only high-risk slices, or ones where the student's confidence is low. Teacher calls stay roughly constant as the app grows.
4. **Keep the budget, cache and incremental scans** already built. The risk-ranked token budget reports what was left unscanned rather than silently dropping it. Cache keys include the prompt and code, so rescanning a new build pays only for changed slices.
5. **Libraries are inventoried, not scanned.** Look up versions in a CVE source rather than having a model read okhttp.
6. **Deduplicate across slices** by sink location, so one bug reached by twenty paths is one finding.

## Dynamic analysis (design, not built)

```
            static findings (candidate sinks, entry points)
                               │
                               ▼
   ┌──────────────── planner (LLM agent) ─────────────────┐
   │ picks target, writes test: intent / deep link / UI   │
   └───────┬──────────────────────────────────┬───────────┘
           │ actions                          │ observations
           ▼                                  │
   ┌──────────────────────┐     ┌─────────────┴────────────────┐
   │ device pool          │     │ oracles                      │
   │ emulator snapshots   │────▶│ Frida hooks on sinks         │
   │ adb / UIAutomator    │     │ canary tokens in traffic,    │
   │ Frida + proxy CA     │     │ logs, files, other apps      │
   └──────────┬───────────┘     │ MITM proxy ─── live backend  │
              │                 └─────────────┬────────────────┘
              ▼                               ▼
   coverage (activities, methods, endpoints)  confirmed finding + evidence
```

**Confirming a vulnerability.** A crash only proves the input reached something. The agent confirms with an **oracle**, decided before the test runs: it plants a canary (a URL on a server we control, a filename, a fake credential) and checks where it ends up:
- a Frida hook on `WebView.loadUrl` sees the attacker URL
- our server receives a request
- a second test app receives the broadcast containing the user's password
- a protected file's content comes back through a provider

Each confirmation is stored with its hook trace and traffic. Crashes and stack traces alone are "needs review", never "confirmed".

**Reaching the right screen.** Static findings already give the target, for example "the sink is in a password-reset activity". The agent first tries to skip the UI: launch the component directly with an intent, or open its deep link. When state is required, it drives the UI from the accessibility tree plus a screenshot, using test accounts. After logging in once, it saves and restores the session instead of logging in every run. Coverage is measured as:
- the share of exported components and declared deep links exercised
- method coverage from a Frida or JaCoCo-style hook
- the share of backend endpoints seen in the proxy, against those referenced in the code

The last shows which features were never reached.

**Scale.** Boot once, then snapshot: every run restores a clean emulator snapshot with the app installed and the proxy CA trusted, in seconds rather than minutes. Run headless emulators (or Cuttlefish) in containers on KVM hosts, as a pool with a queue. Flakiness is handled as data:
- per-step timeouts
- retrying a failed test on a fresh device before believing it
- quarantining devices that fail health checks

Backend state is per run too (separate test accounts or a reset endpoint).

**SSL pinning.** Install the proxy CA as a system CA on a rooted image. Then bypass pinning with Frida scripts that hook the common checks (OkHttp `CertificatePinner`, `TrustManager`, `network_security_config`). If Frida isn't possible, repackage the app with a permissive network config. Most likely to break:
1. **Custom or native pinning:** checks inside a C library, or a hand-rolled one that generic hooks miss.
2. **Root, emulator or Frida detection, and integrity checks:** Play Integrity, signature checks that fail after repackaging, or a backend that refuses the session.
3. **Non-HTTP or unusual transports:** gRPC/HTTP-2 quirks, QUIC (which bypasses the proxy unless blocked), WebSockets, and mutual TLS with a client certificate in the app.

**A bug only dynamic analysis catches:** a server-side IDOR or broken authorisation. Changing an order ID in the API call returns another user's data. The app's code is identical either way. The flaw is in the backend, which static analysis of the APK never sees.

## Models

| Role | Model | Why |
|---|---|---|
| Teacher | `gemini-3-flash-preview` via the Google AI Studio OpenAI-compatible endpoint | Strong reasoning on code, a large context so chunks can be big, and a free tier. The free tier allows about 20 requests a day per model, so the teacher sends 12k-token chunks (InsecureShop fits in 2 calls). |
| Student | `openai/gpt-oss-120b` on Groq | Open weights, cheap and fast, with reliable structured JSON. (`gpt-oss-20b` also works; I switched when its daily quota ran out.) Groq's free tier allows 8k tokens a minute, so the student gets 2.5k-token chunks and `reasoning_effort: low`, which stops reasoning from using up the output budget. |

Both use one OpenAI-compatible adapter. Changing a model is one line under `roles`. A new OpenAI-compatible provider is a `providers` entry. A new wire format is one adapter file registered with `@register_adapter`; `models/anthropic_messages.py` is an example, and `openai` and `anthropic` are already configured providers. I had no Claude or OpenAI key, so those two paths are tested with mocked responses only, and every number above comes from Gemini and Groq. Temperature is 0 for both, but runs still vary, which is why every student side is repeated.

## Running it on a new app

```
vulnscan --app path/to/new.apk loop --repeat 3        # no ground truth: teacher is the reference
vulnscan --app path/to/new.apk --ground-truth labels.yaml evaluate
```

Nothing in `src/` refers to InsecureShop. App path, models, chunk sizes, budgets and match thresholds are in `config/config.yaml`.

A large app still finishes. Code over the token budget is skipped in risk order, the same for both models, and a small share of failing chunks is tolerated (`scan.max_failed_chunk_ratio`). Both are stated as warnings in the results, and recall then covers only the code that was scanned. A scan stopped by a rate limit is not scored; rerunning resumes it from the cache.
