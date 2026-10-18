# Routing & dispatch procedures (orchestrator)

Loaded on demand by `orchestrator` (and useful to `planner`) for cases beyond the hot-path Protocol in
`orchestrator.md`. Read this when classifying a non-obvious request, dispatching a test task, changing existing code,
handling a review request, or facing an empty reply.

## Classify by intent — never funnel everything to `coder`

- "where is / how does X work", locate code, trace a flow → `explorers`. Split into several narrow `explorer` briefs run
  in parallel (one per class / flow / layer), NOT one sweeping brief. If you don't yet know how to split an unfamiliar
  area, send a **recon `explorer` first** (a "map this area" brief → its shape + follow-up briefs), then fan out
  targeted explorers.
- implement or change **production** code (`src/main`) → `coder`.
- write/extend **unit tests** (`src/test`) → `tester`.
- **review** existing code / a commit / diff / branch / test quality → a reviewer subagent (see "Review requests").

**Two common slips:**

- sending **test-writing to `coder`** — tests are `tester`; `coder` only writes `src/main`.

**Decide the zone before dispatching:** does it touch `src/test` (a `*Test`, step-def)? → a tester, full stop.

## Test tasks: explorer first → writer → review (never writer-first)

**Tests NEVER go to `coder`** — it has `src/test: deny`, so a test task to it is *guaranteed* to fail.

- Includes **fixing/changing** an existing test («исправь тесты» is a `tester` job — editing a test touches `src/test`).
- The one exception: changing **production** `src/main` so a failing test passes (fix the code, not the test) → `coder`.
- `coder` bounces a test task, or returns empty on a `src/test` task (that's `deny`) → re-dispatch to
  `tester`; never retry `coder`.
- A `tester` returning "up to date" must still report **what it checked** (which tests exist + that they pass); a bare
  "up to date" is a failed task.

A `tester` dispatched **cold** reads the whole project — slow and context-blowing. So writing/extending tests is **three
dispatches**:

1. **Explorer first.** Map what the test needs: class/flow under test (`path:line`), collaborators to mock/stub,
   conventions of neighboring tests (assertion framework, fixtures, DI, tags). Broad area → fan out several narrow
   briefs.
2. **Then the writer** with those findings in `inputs`, so it reads **narrowly** — only the class under test and its
   nearest peers.
3. **Then the review gate** (`test-reviewer`).
   Skip the explorer pass only for a trivially-scoped tweak whose location and conventions are already spelled out.

## Changing existing code (incl. a "specific spot") — explorer-probe first

For a **change to EXISTING code** — even a one-liner — don't go straight to `coder` blind (you can't see the code;
«location known» ≠ «isolated/tested»). First send a **minimal `explorer` probe** that returns:

- **callers** of the thing being changed (find-usages);
- whether a **covering test** exists.
  Pack these into `coder`'s `inputs`: the caller list (for its >5-callers decomposition check), the spec to preserve,
  and the coverage flag. Straight to `coder` only for **purely new / additive** code with nothing to ripple. For
  genuinely large/risky work, recommend the human run it through `planner`.

## Review requests → a reviewer subagent (never review it yourself)

You hold no rubric and **no git/read** — you literally cannot read the diff. So:

- **First classify the diff (you can't see it):** send a quick `explorer` to report what the ref/change touches —
  `src/main` / `src/test` / mix.
- Dispatch by that classification: `code-reviewer` (production) and/or `test-reviewer` (tests); a mixed change →
  **both**. Pass the ref (commit SHA / branch / range / area) in `inputs`. The reviewer runs `git show`/`git diff`
  itself, reads, **writes `opencode-reviews/<subject>.code-review.md`** (or `.test-review.md`), and returns PASS/FAIL.
- After it returns, tell the human which reviewer ran and the **report path** — that file existing is the proof the
  review happened (no file ⇒ you skipped the dispatch).
- For a **pure review**, `planner` is safer (it can't implement); `orchestrator` may proceed to fix. Don't auto-fix on a
  standalone review request.

## Three outcomes for a red existing test (after a `coder` change)

"Affected existing tests" = the changed class's `*Test` **AND** tests that exercise it via collaboration — reuse the
explorer caller-list to find those (a change to `Foo` can be covered by `BarTest`, not `FooTest`); run those too.
Require `coder` to **name which test covers the changed branch**; if none can be named, treat it as **no coverage**
(flag to human), not a silent green — a green run of `*FooTest` does NOT prove the changed branch was exercised.

A red existing test has **three outcomes** — classify, don't guess:

- (a) the change was **intended** → the test is outdated → `tester` **updates** it;
- (b) the change is a **bug** → `coder` fixes `src/main`;
- (c) a **mechanical** break (renamed method/signature) → the tester updates the references;
- (env/infra) connection-refused / no context / missing container = **not a regression** → surface to the human.
  The `explorer` surfaces «was vs now»; the **human confirms whether the new behavior is intended** (a vs b). Never gut
  a failing test to green. Both the fix loop (b/c) and the test-update loop (a) are capped at **≤2 rounds** (see the
  caps table in `orchestrator.md`).

## Empty reply (#18423) — retry, don't redo

A subagent that clearly did the work but returns an **empty / result-less reply** is OpenCode's Ollama forwarding bug:
the edits usually landed on disk, only the text didn't come back (textbook: a `tester` that ran a green `./gradlew` then
fell silent). Do NOT conclude «no answer», stall, or redo the work yourself.

- **First rule out wrong-agent:** empty reply from `coder` on a `src/test` task = `coder`'s `deny`, NOT the glitch →
  re-dispatch to `tester` / `automation-tester`; never retry `coder`.
- **Zone-correct → retry the same subagent (≤2 times)**, adding to `inputs`: «Return your result as text — the exact
  command you ran + pass/fail + failing details; an empty reply or a bare "done" fails the task.» It almost always comes
  back.
- **After 2 empty replies from the same agent on the same task → stop**, never re-dispatch it again. Re-route to the
  sibling if it could be a zone issue, otherwise surface to the human — the change may already be on disk, so ask them
  to verify rather than re-run blindly. (Applies regardless of presumed cause, so a wrong-agent loop can't spin.)
