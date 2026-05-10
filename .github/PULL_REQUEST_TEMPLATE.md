<!--
  Thanks for opening a PR. A few quick reminders before you submit:
    1. CI must be green (cargo fmt --check, clippy -D warnings, tests).
    2. One concern per PR. Bug fixes don't carry refactors.
    3. Security issues belong in a private advisory, not a PR.
       See SECURITY.md.
  Delete this comment block before submitting.
-->

## Summary

<!-- What changed and why. 2–3 bullets is plenty. -->

## Linked issue

<!-- e.g. "Closes #42" or "Refs #42". Required for non-trivial work. -->

## Test plan

<!--
  Bulleted list. What did you actually run? What new tests did you add?
  What couldn't you validate, and why? Be specific — "ran tests" is
  not a test plan.
-->

- [ ] `make fmt` is clean
- [ ] `make clippy` is clean
- [ ] `make test` passes
- [ ] New tests added for new code paths
- [ ] Hand-smoked any client UI changes (note what you ran below)
- [ ] Commits are signed off (`git commit -s`) — see CONTRIBUTING.md

## Risks / tradeoffs

<!-- Anything reviewers should poke at? Threat-model implications? -->

## Migration / operational notes

<!--
  Schema changes? New env vars? Breaking config changes? List them
  here. If none, write "none".
-->
