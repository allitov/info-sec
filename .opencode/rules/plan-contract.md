# Plan-contract template

Written by `planner` (its sole deliverable), executed by `orchestrator`, kept anchored across compaction by
`plan-anchor` / `plan-checkbox-sync`. Create `opencode-plans/<task-id>.md` (make the folder if absent) using exactly
this structure:

```markdown
# Plan contract: <task-id>

> Disk source of truth. Re-read before each decision and after any compaction.

**Goal:** <one paragraph, in verifiable terms>
**active:** <id of the task being executed now, or —>

## open_questions

- [ ] Q1: <question> — answer: <…>

## backlog

- [ ] **Task1** — <short title>
    - **agent:** coder | tester | code-reviewer | test-reviewer | explorer
    - **inputs:** <everything the subagent needs — paths, signatures, explorer findings>
    - **deps:** []
    - **acceptance:** <verifiable: a passing test / a specific output / a permission denial>
    - **description:** <what to do, atomically>
    - **touched:** <left empty by planner; orchestrator fills it on tick with the files the subagent reported changing —
      a granular rollback map for the human>
```

## Rules for the contract

- **Every backlog task starts with a `- [ ]` checkbox** carrying `agent` (from the Routing map in
  `/.opencode/rules/routing.md`), `inputs`, `deps`, `acceptance`, `description`. `orchestrator` flips `- [ ]` → `- [x]`
  and fills `touched:` (the files the subagent changed) on tick, so a task without a checkbox cannot be tracked.
- Fill `active:` (the current task id) and `open_questions`.
- **`deps` must be acyclic**, and every id in a task's `deps` must exist in the backlog — a cycle leaves `orchestrator`
  with no ready task and stalls it. Trace each chain to a `deps: []` task before the human gate.
