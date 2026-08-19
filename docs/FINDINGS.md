# Checkov baseline triage

Scan date: 2026-08-19
Tool: Checkov 3.3.11
Target: `terraform/main.tf`
Result: **19 passed, 44 failed, 0 skipped**

---

## Headline

44 findings is not 44 problems. Grouped by root cause:

| Root cause | Findings produced | Lines of Terraform |
|---|---|---|
| IAM policy: `Action: "*"` on `Resource: "*"` | 9 | 1 |
| S3 public access block all `false` | 5 | 4 |
| Security group ingress `0.0.0.0/0` on all ports | 3 | 1 |
| RDS misconfiguration (multiple distinct issues) | 13 | ~6 |
| S3 bucket missing configuration blocks | 7 | absent |
| EC2 instance missing configuration | 5 | absent |
| VPC missing configuration | 2 | absent |

**Five root causes account for roughly 30 of the 44 findings.**

---

## Tier 1 — blocking. Fix before merge.

### CKV_AWS_17 — RDS `publicly_accessible = true`
`aws_db_instance.postgres`

**Worked.** Public accessibility and the hardcoded password are individually
survivable and jointly fatal. A public database with a strong random credential
is exposed but hard to break; a weak credential on a private-subnet database is
unreachable. Together they require no attacker skill. Checkov listed these as
two unrelated rows — the risk lives in the combination, which the tool cannot see.

Encryption at rest (CKV_AWS_16) ranks lower: it defends against stolen disks and
leaked snapshots, not against an attacker who logs in with valid credentials.

### CKV_AWS_24 — SSH open to `0.0.0.0/0`
`aws_security_group.web`

**Worked.** `0.0.0.0/0` is not an unset value — it is an explicit rule matching
all 4.3 billion IPv4 addresses. Discovery is not a barrier: masscan sweeps the
full IPv4 space on one port in minutes, Shodan and Censys index the results
continuously, and AWS publishes its IP ranges. Time from a fresh public IP to
first unsolicited SSH attempt is measured in minutes.

No targeting is required. Automated botnets try `root:root`, `admin:admin`,
`ubuntu:ubuntu` against every open port 22 they find. With no key-only auth and
no fail2ban configured, a successful login is plausible — the "followed by a
success" half of Wazuh rule 40112 from the Home SOC Lab.

Remediation options, worst to best: source `/32` (breaks on ISP IP rotation,
and anything compromised inside that network is now inside the allowed range);
bastion host (single hardened logged entry point); **SSM Session Manager**
(removes the ingress rule entirely — no port to scan, no keys to rotate, IAM-
controlled, CloudTrail-logged). Restrict → centralise → eliminate.

Note: routing and security groups are different layers. A private subnet has no
route from the internet, so a `/32` allow rule on an instance in one is
decoration. Security groups filter traffic that routing already delivered.

### CKV_AWS_63, 62, 286, 287, 288, 289, 290, 355, CKV2_AWS_40 — IAM wildcard
`aws_iam_role_policy.app_admin` — nine checks, one line

**Worked.** Same finding Prowler rated Critical in the Cloud Security Hardening
project — now caught pre-apply instead of post-deployment.

Attack chain: SSRF in the web app → attacker forces a request to
`http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role`
(link-local, reachable only from inside the instance, which is why SSRF is the
delivery mechanism) → returns `AccessKeyId`, `SecretAccessKey`, `Token` → the
attacker exports these on their own machine and is administrator of the entire
account, from anywhere. Not the instance. The account.

This is Capital One 2019, ~100 million records.

**Three findings compose into this: CKV_AWS_79 (IMDSv1), CKV_AWS_63 (wildcard
role), CKV_AWS_130 (public IP subnet). Checkov reports them as three unrelated
rows in a flat list of 44 and gives no indication they are connected. Scanners
evaluate resources in isolation; attackers exploit paths between resources.**

### CKV_AWS_53, 54, 55, 56, CKV2_AWS_6 — S3 public access block disabled
`aws_s3_bucket_public_access_block.data` — five checks, one block

**Worked.** No live exploit here. Nothing in this config makes the bucket
public, and disabling the block grants no one access — modifying a bucket policy
requires `s3:PutBucketPolicy` on the account, which an outside attacker does not
have.

This is a **missing guardrail, not a vulnerability**. The block is an override
that says "ignore any public policy or ACL." With all four `false`, that safety
net is gone: the bucket is private today, and nothing stops a future mistake —
an intern, a misapplied module, an unreviewed apply — from exposing it. Every
major public-S3 breach (Verizon, Accenture, Booz Allen) was exactly this.

Why CKV_AWS_20 and CKV_AWS_57 PASS while these FAIL: they measure different
things. The ACL checks ask *is the bucket public now* (no). The block checks ask
*is the safety switch on* (no). Door closed, lock removed.

---

## Tier 2 — advisory. Real risk, would not block a build.

| Check | Resource | Why it matters | Blast radius if exploited |
|---|---|---|---|
| CKV_AWS_79 (IMDSv1) | aws_instance.web | *Worked — see IAM chain above. `http_tokens = "required"` forces a PUT to obtain a session token first; SSRF controls a URL, not the HTTP method or headers, so the chain breaks. Does NOT stop an attacker with real code execution.* | |
| CKV_AWS_16 | aws_db_instance.postgres | | |
| CKV_AWS_8 | aws_instance.web | | |
| CKV_AWS_145 | aws_s3_bucket.data | | |
| CKV_AWS_21 | aws_s3_bucket.data | | |
| CKV_AWS_18 | aws_s3_bucket.data | | |
| CKV2_AWS_11 (VPC flow logs) | aws_vpc.main | | |
| CKV2_AWS_12 (default SG) | aws_vpc.main | | |
| CKV_AWS_130 | aws_subnet.public | | |
| CKV_AWS_25, CKV_AWS_260 | aws_security_group.web | *Same root cause as CKV_AWS_24 — the `0-65535` range covers RDP and HTTP too.* | |
| CKV_AWS_382 (egress) | aws_security_group.web | | |
| CKV_AWS_161 (RDS IAM auth) | aws_db_instance.postgres | | |
| CKV_AWS_129, CKV2_AWS_30 (RDS logging) | aws_db_instance.postgres | | |
| CKV2_AWS_41 (no instance profile) | aws_instance.web | | |

**Prompt for each blank:** what does an attacker gain, or what does a defender
lose, if this stays as-is? If the honest answer is "nothing directly," it belongs
in Tier 3.

---

## Tier 3 — not security. Cost, availability, or hygiene.

| Check | Resource | Actual category |
|---|---|---|
| CKV_AWS_157 (Multi-AZ) | aws_db_instance.postgres | |
| CKV_AWS_135 (EBS optimized) | aws_instance.web | |
| CKV_AWS_126 (detailed monitoring) | aws_instance.web | |
| CKV_AWS_118 (enhanced monitoring) | aws_db_instance.postgres | |
| CKV_AWS_353 (performance insights) | aws_db_instance.postgres | |
| CKV_AWS_144 (cross-region replication) | aws_s3_bucket.data | |
| CKV2_AWS_61 (lifecycle config) | aws_s3_bucket.data | |
| CKV2_AWS_62 (event notifications) | aws_s3_bucket.data | |
| CKV2_AWS_60 (copy tags to snapshots) | aws_db_instance.postgres | |
| CKV_AWS_226 (auto minor upgrades) | aws_db_instance.postgres | |
| CKV_AWS_293 (deletion protection) | aws_db_instance.postgres | |
| CKV_AWS_23 (SG descriptions) | aws_security_group.web | |

**Prompt:** label each as availability / cost / operability / compliance. This
tier is the argument for `soft_fail` — blocking a developer's build over Multi-AZ
on a dev database is how teams learn to disable the gate.

---

## Scanner limitations observed

### 1. False negative — CKV_AWS_88 PASSED
"EC2 instance should not have public IP" passed. The instance sits in a subnet
with `map_public_ip_on_launch = true` and will receive a public IP. Checkov
checked the instance resource for `associate_public_ip_address`, found nothing,
and passed — it did not follow the reference into the subnet.

### 2. Missed entirely — hardcoded RDS password
**Worked.** The secrets framework ran and reported nothing. Secret scanners match
on **patterns**: high Shannon entropy, and known credential formats (`AKIA…`,
`ghp_…`, `-----BEGIN PRIVATE KEY-----`). `Password123!` is low-entropy,
human-readable English matching no known format.

**A weak password evades secret scanners better than a strong one.** Rotate to a
random 32-character string and the scanner starts catching it. The tool is
structurally blind to exactly the credentials most likely to be guessed.

### 3. No composition analysis
**Worked.** See the IAM section: three separately-listed findings chain into full
account compromise. Flat lists cannot express attack paths.

### 4. Severity is not risk
*Prompt: CKV_AWS_79 is rated medium. In the chain above it is the pivot. What
does that tell you about consuming vendor severity ratings uncritically?*

---

## Credential handling — the committed password

**Worked.** Git stores every commit permanently. Editing `main.tf` and committing
creates a new commit; the old one still contains the password and `git log -p`
reads it. Force-pushing rewritten history is unreliable — GitHub retains orphaned
objects, forks keep them, and anyone who cloned already has it.

Correct order:
1. **Rotate the credential.** Always first. It is burned the moment it is
   committed — treat it as public.
2. Remove from the working tree; move to Secrets Manager or SSM Parameter Store,
   referenced by a Terraform data source.
3. Optionally scrub history with `git filter-repo` or BFG — **after** rotating,
   never instead of it.

Rotate, then clean. Reversing this is the classic mistake: hours spent rewriting
history while the live credential stays valid.

---

## Suppressions and justifications

*Format — every suppression needs a written reason:*

```hcl
resource "aws_db_instance" "postgres" {
  # checkov:skip=CKV_AWS_157:Multi-AZ is an availability requirement, not a security control; single-AZ accepted for this non-production lab
```

| Check | Justification | Reviewed by |
|---|---|---|
| | | |

---

## Gate policy

*The decision this whole project exists to make. Fill in before flipping
`soft_fail` to `false`.*

- Blocking:
- Advisory:
- Rationale for the split:
- What happens when a developer needs an exception:

---

## Remediation log

| Date | Change | Checks cleared | Failed count after |
|---|---|---|---|
| 2026-08-19 | baseline | — | 44 |
