# AFL++ Fuzz Testing Workflows

## Workflow 1: CI Pipeline Integration

```
Code pushed to branch
       |
Fuzzing harness compiled with afl-clang-fast + ASan
       |
Corpus restored from CI cache
       |
AFL++ runs in secondary mode for fixed duration
       |
[No crashes] --> Corpus updated in cache, pipeline passes
[Crashes found] --> Pipeline fails, crash artifacts uploaded
       |
Developer triages crashes
       |
Fix applied, re-run confirms no regression
```

## Workflow 2: Nightly Fuzzing Campaign

```
Scheduled nightly trigger (cron)
       |
Build instrumented binary + CmpLog binary
       |
Restore merged corpus from last run
       |
Launch parallel AFL++ instances (nproc count)
       |
Run for 4-8 hours
       |
Collect results from all instances
       |
afl-cmin merges and minimizes corpus
       |
Deduplicate crashes by stack hash
       |
New crashes create Jira/GitHub issues automatically
       |
Updated corpus cached for next run
```

## Workflow 3: Crash Triage and Fix

```
Crash file identified in findings/
       |
Reproduce crash with ASan-instrumented binary
       |
Capture ASan stack trace and error type
       |
Minimize crash input with afl-tmin
       |
Identify root cause from stack trace
       |
Develop fix and add crash input as regression test
       |
Verify fix by re-running AFL++ with crash input
       |
Update corpus to include edge case inputs
```
