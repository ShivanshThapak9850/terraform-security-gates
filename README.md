# terraform-security-gates

Shift-left security for Infrastructure as Code: taking a deliberately insecure
Terraform configuration from **44 Checkov findings to 0**, with every suppression
justified in writing.

> ### ⚠️ Vulnerable by design — read before using anything here
>
> The Terraform in `terraform/` began as intentionally insecure scan-target
> material. The Git history contains a **fake credential (`Password123!`)** in
> the baseline commit. This is deliberate: it demonstrates that secret scanners
> match on entropy and known credential formats, not password strength — see
> [`docs/FINDINGS.md`](docs/FINDINGS.md).
>
> No infrastructure in this repository was ever deployed. Nothing here is a
> template. Do not copy the baseline configuration.

---

## Why this project exists

A previous project used **Prowler** and **GuardDuty** to find misconfigurations
in a *running* AWS account  detective control. The over-permissioned IAM role it
flagged as Critical already existed, in the account, and was caught afterwards.

This project is the preventive half. Checkov catches the same class of finding at
pull-request time, before `terraform apply`. Same problem, caught earlier, at a
fraction of the cost.

Both halves matter. Detection finds what prevention missed; prevention stops what
detection would have found too late.

---

## Results

| | Passed | Failed | Skipped |
|---|---|---|---|
| Baseline | 19 | **44** | 0 |
| Remediated | 50 | **0** | 8 |

Full triage and reasoning: [`docs/FINDINGS.md`](docs/FINDINGS.md)
Raw baseline output: [`docs/baseline-scan.txt`](docs/baseline-scan.txt)

**44 findings were not 44 problems.** Five root causes produced roughly 30 of
them:

| Root cause | Findings | Lines of Terraform |
|---|---|---|
| IAM policy `Action: "*"` on `Resource: "*"` | 9 | 1 |
| S3 public access block all `false` | 5 | 4 |
| Security group ingress `0.0.0.0/0`, all ports | 3 | 1 |
| RDS misconfiguration | 13 | ~6 |
| Missing S3 configuration resources | 7 | absent |

Counting findings measures scanner output. Counting root causes measures risk.

---

## What was fixed

**RDS** - removed the hardcoded password in favour of
`manage_master_user_password`, so AWS generates, stores and rotates the
credential in Secrets Manager and it never enters source control. Disabled public
accessibility, enabled encryption at rest, backups, deletion protection, IAM
authentication and log exports.

**IAM** - replaced `Action: "*"` on `Resource: "*"` with `s3:GetObject` and
`s3:ListBucket` scoped to one bucket ARN and its object ARN. Renamed the resource
from `app_admin` to `app_read_data`; a name that overstates its scope is a
future incident.

**Security groups** - removed the SSH ingress rule entirely rather than narrowing
it, and attached `AmazonSSMManagedInstanceCore` so administration happens through
Session Manager. No port 22 to scan, no keys to rotate, IAM-controlled and
CloudTrail-logged. Egress restricted from all traffic to 443 only.

**EC2** - required IMDSv2 (`http_tokens = "required"`), encrypted the root
volume, moved the instance to a private subnet, attached an instance profile.

**S3** - enabled all four public access block settings, KMS encryption with
bucket keys, versioning and access logging.

**VPC** - emptied the default security group, enabled flow logs.

---

## The attack chain the scanner could not see

Three findings, reported as unrelated rows in a flat list of 44:

- `CKV_AWS_79` - IMDSv1 enabled (rated medium)
- `CKV_AWS_63` - IAM wildcard action (one of nine on the same line)
- `CKV_AWS_130` - subnet assigns public IPs

Chained: an SSRF bug in the web application lets an attacker force a request to
`169.254.169.254/latest/meta-data/iam/security-credentials/app-role`. IMDSv1
answers a plain GET with temporary STS credentials. Those credentials carry
`Action: "*"` on `Resource: "*"`, so the attacker exports them on their own
machine and is administrator of the entire account — not the instance, the
account.

This is the Capital One breach pattern (2019, ~100 million records).

IMDSv2 breaks it by requiring a `PUT` to obtain a session token first. SSRF
typically controls a URL, not the HTTP method or headers, so the chain fails at
the first step. It does **not** protect against an attacker with code execution
on the host — that is what least privilege is for.

**Scanners evaluate resources in isolation. Attackers exploit paths between
resources.**

---

## Where the scanner was wrong

**False negative - `CKV_AWS_88` passed.** "EC2 instance should not have public
IP" passed while the instance sat in a subnet with
`map_public_ip_on_launch = true`. Checkov checked the instance resource for
`associate_public_ip_address`, found nothing, and passed — it did not follow the
reference into the subnet.

**Missed entirely - the hardcoded RDS password.** The secrets framework ran and
reported nothing. Secret scanners match on high Shannon entropy and known formats
(`AKIA…`, `ghp_…`, PEM headers). `Password123!` is low-entropy, human-readable
English matching no known pattern. **A weak password evades secret scanners
better than a strong one does.**

**Parse errors read as clean scans.** A syntax error produced
`Passed: 0, Failed: 0, Parsing errors: 1`. With `soft_fail: true`, a broken
Terraform file passes the gate more easily than a working one.

**A passing check is not a safe design.** VPC flow logs currently write to the
same bucket as application data. It satisfies `CKV2_AWS_11` and is still wrong —
a compromised bucket should not hold its own audit trail. Deliberately left
unfixed and documented.

---

## Suppressions

Eight, each with a written justification in the Terraform itself:

```hcl
# checkov:skip=CKV_AWS_157:Multi-AZ is an availability control, not security; single-AZ accepted for a non-production lab
```

The pattern in every one: **why this is not a security control in this context**,
not "this is inconvenient." Multi-AZ, Performance Insights, cross-region
replication and lifecycle rules are availability, performance and cost decisions
wearing a security scanner's clothing. Blocking a developer's build over Multi-AZ
on a dev database is how teams learn to disable the gate.

---

## Reproducing

```bash
pipx install checkov
checkov -d terraform/ --compact
```

Nothing here is ever applied. No AWS account, no credentials, no cost.

To see the baseline:

```bash
git log --oneline
git show <baseline-commit>:terraform/main.tf
```

---

## Tooling

Checkov 3.3.11 · Terraform · AWS provider ~> 5.0

---

## Status

- [x] Baseline scan and triage
- [x] Remediation to zero findings
- [x] Justified suppressions
- [ ] Trivy - dependency, secret and container image scanning
- [ ] GitHub Actions pipeline integration
- [ ] Gate policy: which checks block a merge, which only warn
- [ ] Kyverno admission policies (separate track, requires a cluster)
