# Finding Triage Playbook

This playbook maps `volt` finding types to practical triage actions. Use it after confirming the run was in scope and the relevant source completed with acceptable reliability.

## General Workflow

1. Validate source reliability first.
2. Triage high/medium severity findings first.
3. Confirm target ownership and authorization.
4. Capture reproducible evidence before remediation.
5. Re-run `volt` after fixes to confirm closure.

Interpret findings conservatively:

- Search-index results indicate possible exposure, not guaranteed live exposure.
- Cloud storage results indicate existence or publicability signals, not full data impact by themselves.
- Takeover results indicate a reclaimability lead until provider ownership is verified.

## 1) `indexed_leak`

What it means:
- A search/index provider returned a potentially sensitive URL pattern.

Triage:
1. Confirm URL is in owned scope.
2. Recheck the URL directly in an authorized environment.
3. Determine if content is still reachable or stale-index residue.
4. If live, classify data sensitivity and exposure window.

Common fixes:
- Remove exposed file/content.
- Add access controls and denylisting.
- Purge index/cache where supported.

## 2) `s3_bucket`

What it means:
- Bucket naming/existence/publicability signal from anonymous AWS endpoint probes.

Triage:
1. Validate the bucket belongs to the target org.
2. Check public access block settings and bucket policy.
3. Confirm object-level exposure risk, not only listability.

Common fixes:
- Enable/verify Block Public Access controls.
- Tighten bucket/object policies and ACL posture.
- Move sensitive objects to private storage paths.

## 3) `gcp_bucket`

What it means:
- Bucket existence/publicability signal from anonymous GCS probes.

Triage:
1. Validate bucket ownership and intended exposure.
2. Review IAM/public access posture.
3. Confirm whether object reads are publicly possible.

Common fixes:
- Remove `allUsers`/`allAuthenticatedUsers` bindings where unintended.
- Enforce least-privilege IAM at bucket/object scope.
- Rotate or relocate sensitive content.

## 4) `azure_blob_container`

What it means:
- Container-level or blob-level anonymous read signal from Azure Blob probes.

Triage:
1. Confirm storage account/container ownership.
2. Distinguish list access from blob-only access.
3. Validate account-level public access settings and container policy.

Common fixes:
- Disable anonymous public access where not required.
- Set container access level to private.
- Remove or restrict public blob paths for static content.

## 5) `subdomain_takeover`

What it means:
- CNAME/provider fingerprint suggests reclaimable external service endpoint.

Triage:
1. Confirm DNS record ownership and intended target.
2. Validate fingerprint match and provider reclaimability.
3. Assess business impact of hostname compromise.

Common fixes:
- Remove stale DNS records.
- Reclaim target resource in provider platform.
- Add lifecycle controls for DNS and external service deprovisioning.

## 6) `subdomain`

What it means:
- Passive host inventory discovered from CT/subfinder/amass.

Triage:
1. Confirm active ownership and environment mapping.
2. Decommission stale or unknown hosts.
3. Feed verified inventory into continuous monitoring.

## Reliability Gating

Before closing findings, review:

- `source_health.<module>.status`
- `source_health.<module>.error_types`
- `source_health.<module>.error_samples`
- `source_health.<module>.notes`

If a relevant source is `partial` or `error`, rerun after remediation of source issues to avoid false negatives.

If a source is degraded, treat negative results from that source as inconclusive.
