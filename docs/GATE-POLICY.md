# Gate policy

How Checkov findings are enforced in CI: what blocks a merge, what only warns,
how exceptions are granted, and what breaks as the team grows.

Written before flipping `soft_fail` to `false` — deliberately, while the scan was
clean and no failing build was applying pressure to the decision.

---

## 1. What blocks a merge

**Reasoning: blast radius. Mechanism: an explicit list of check IDs.**

The right question for any finding is not "how severe is this check" but "if this
resource is compromised, what else falls with it." A wildcard IAM policy attached
to nothing has no blast radius; the same policy on an instance role reachable via
SSRF is account takeover.

Blast radius cannot be the *mechanism*, because:

- Checkov exposes no blast-radius field. Severity is filterable
  (`--check-severity HIGH`); radius is not.
- Radius is contextual, not intrinsic to the check. It depends on what else
  exists in the environment — which a per-resource scanner cannot see.
- Operationalising it would mean hand-classifying ~1000 checks and
  re-classifying on every version bump.

This project already demonstrated the gap: `CKV_AWS_79` (IMDSv1) is rated medium
in isolation and was the pivot in a full account-compromise chain.

So blast radius selects the categories; an enumerated list executes them.

### Blocking

| Category | Check IDs | Why it blocks |
|---|---|---|
| Public exposure | CKV_AWS_17, CKV_AWS_24, CKV_AWS_25, CKV_AWS_53, 54, 55, 56, CKV2_AWS_6 | Reachable from the internet by anyone, no attacker skill required |
| IAM over-permission | CKV_AWS_62, 63, 286, 287, 288, 289, 290, 355, CKV2_AWS_40 | Compromise of one resource becomes compromise of the account |
| Encryption at rest | CKV_AWS_16, CKV_AWS_8, CKV_AWS_19, CKV_AWS_145 | Data loss is unrecoverable; cannot be retrofitted after a breach |
| Metadata service | CKV_AWS_79 | Breaks the SSRF-to-credential-theft chain |

Roughly 18 check IDs.

### Warning only

Everything else — logging, monitoring, availability, cost, and hygiene checks.

Blocking a developer's build over Multi-AZ on a dev database is how teams learn
to disable the gate. A gate that fires on things nobody considers security loses
the authority to fire on things that are.

### Why an enumerated list rather than a severity filter

`--check-severity HIGH` silently expands whenever the vendor re-rates a check.
The pipeline breaks on a Tuesday because Prisma Cloud changed a rating nobody
reviewed.

An explicit list changes only when a human decides it changes. The difference is
between a gate we control and one the vendor controls.

---

## 2. Exceptions

### The problem

Any developer can bypass the gate by typing one line:

```hcl
# checkov:skip=CKV_AWS_16:temporary migration replica, deleted Monday
```

The check is skipped, the pipeline goes green, the merge proceeds. A gate with an
unreviewed bypass is not a gate.

The opposite failure is equally real: a gate with **no** bypass gets disabled
entirely the first time it blocks an incident fix at 6pm on a Friday.

**The goal is not to make the insecure path impossible. It is to make it slower,
reviewed, and permanently visible.**

### Enforcement lives in Git, not in the scanner

The scanner reports. Branch protection decides who can merge. Building approval
logic into the CI job is the wrong layer — it becomes a script anyone can edit.

```
# .github/CODEOWNERS
terraform/    @security-team
```

Combined with branch protection on `main`:

- Require pull request review before merge
- Require status checks to pass
- **Dismiss stale approvals when new commits are pushed** — without this, a clean
  PR gets approved and the skip line is pushed afterwards

### Suppressions must be visible

A skip comment inside a 400-line diff is easy to miss. A second CI step greps for
newly added `checkov:skip` lines and comments on the PR:

> This PR adds 1 suppression: CKV_AWS_16

The reviewer is then approving an exception, not skimming a diff.

### Suppressions must expire

Checkov has no TTL. Nothing removes a skip on its own. Every suppression carries
a date and a ticket:

```hcl
# checkov:skip=CKV_AWS_16:temporary migration replica, no customer data — EXPIRES 2026-08-25, ticket SEC-1421
```

A scheduled job greps for expired dates and files a ticket.

Without expiry, every exception is permanent. In two years the Terraform holds
forty skips nobody remembers agreeing to. **Gates do not decay by being removed.
They decay by accumulating exceptions.**

---

## 3. What breaks at fifty developers

Not permissions — CODEOWNERS assigns to a team, so headcount does not change that
line. Not suppression volume directly — that scales with how often the gate
blocks legitimate work, not with headcount.

What actually breaks:

**The security team becomes the bottleneck.** Every Terraform PR needs their
review. Two engineers against thirty PRs a day means merges wait hours. Within a
month people ask to join `@security-team` "for velocity," and the exception path
quietly becomes the normal path.

**Suppression copy-paste.** One approved skip line gets copied into the next
developer's Terraform, justification included, for a situation it no longer
describes. Thirty instances of `CKV_AWS_16` all citing a migration that finished
last year.

**Nobody owns the aggregate.** Each suppression was reasonable when reviewed
individually. Nobody ever looks at all forty together and asks whether the gate
still does anything.

### Responses

**Fix the source, not the exception.** Twenty developers tripping `CKV_AWS_16` is
not twenty careless developers — it is a missing encrypted-by-default RDS module.
Every recurring suppression marks a paved road that does not exist yet. This is
the platform-engineering answer, and it is the durable one.

**Move policy out of the resource.** Central `.checkov.yml` with documented
exceptions, owned by the security team, reviewed as its own artifact rather than
buried in application Terraform.

**Measure the gate.** Track suppression count over time. A rising count means the
policy is mismatched to reality, not that developers are careless.

### Underlying principle

A control that depends on humans being disciplined at scale will fail at scale.
Controls that hold are the ones where the secure path is also the easy path —
which is why a hardened module beats a blocking check.

---

## Current status

`soft_fail: true` — all checks advisory. This policy is written; enforcement is
not yet enabled.

Before flipping to `false`:

- [ ] CODEOWNERS file added
- [ ] Branch protection configured on `main`
- [ ] Suppression-visibility CI step added
- [ ] Expiry dates backfilled on the 8 existing suppressions
