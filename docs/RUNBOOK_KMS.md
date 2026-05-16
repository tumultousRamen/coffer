# Runbook — AWS KMS Operations

Operational procedures for the KMS KEK that anchors envelope encryption (per [ADR 0003](adr/0003-envelope-encryption-shape.md)). Loss or misconfiguration of this key brick every credential in the vault — the procedures below are non-negotiable.

## Key facts

- **Key purpose:** symmetric AES-256 KMS Customer Master Key (CMK).
- **Alias:** `alias/coffer-tenant-kek`.
- **Account isolation:** lives in a dedicated AWS account (per brief — separate from app account).
- **Usage:** only `Encrypt` and `Decrypt` of per-tenant DEKs. Never used to encrypt credential bytes directly.
- **Automatic rotation:** enabled (AWS KMS rotates the backing material annually; ciphertext under older versions remains decryptable transparently).

## Initial setup

```bash
aws kms create-key \
  --description "coffer tenant-DEK KEK" \
  --key-usage ENCRYPT_DECRYPT \
  --customer-master-key-spec SYMMETRIC_DEFAULT \
  --multi-region false

aws kms create-alias \
  --alias-name alias/coffer-tenant-kek \
  --target-key-id <key-id>

# Enable automatic rotation
aws kms enable-key-rotation --key-id <key-id>

# IAM policy: only the vault service role may Encrypt/Decrypt
# (and only coffer-migrate may additionally call ReEncrypt during migration)
```

## Disable accidental deletion

**This is the most important step.** A deleted KMS key is irrecoverable after the pending-delete window expires. **All credentials encrypted under it become permanent ciphertext.**

```bash
# Apply a key policy that denies kms:ScheduleKeyDeletion to all principals
# except a break-glass role that requires MFA.
aws kms put-key-policy --key-id <key-id> --policy file://policies/kek-no-delete.json
```

In production, the break-glass role should:
- Require hardware MFA.
- Be auditable in CloudTrail.
- Be assumed only via a written change-management ticket.

## Routine operations

### Verify the key is healthy

```bash
aws kms describe-key --key-id alias/coffer-tenant-kek
# Check: KeyState = "Enabled", KeyManager = "CUSTOMER"
```

### Rotate the key

KMS automatic rotation handles backing-material rotation transparently. **No application action is required.** Ciphertext encrypted under previous versions remains decryptable.

For **manual rotation** (e.g. compromise suspected), generate a new CMK and re-wrap every tenant DEK against the new key:

```bash
# 1. Create new KEK
aws kms create-key --description "coffer tenant-DEK KEK v2" ...

# 2. Run coffer-migrate against the new key — this re-wraps DEKs, ciphertext on
#    credential rows is unchanged (the DEK itself is the same, only its KMS wrapper changes)
coffer-migrate \
  --source-pg-url $COFFER_PG_URL \
  --source-aws-region $COFFER_AWS_REGION --source-kms-key-id alias/coffer-tenant-kek \
  --dest-pg-url   $COFFER_PG_URL \
  --dest-aws-region $COFFER_AWS_REGION   --dest-kms-key-id alias/coffer-tenant-kek-v2

# 3. Update vault config to point at the new alias, redeploy
# 4. Verify reads succeed end-to-end, then disable (NOT delete) the old key
aws kms disable-key --key-id alias/coffer-tenant-kek
```

## Disaster scenarios

### KMS key accidentally scheduled for deletion

1. CloudTrail alarm fires (`kms:ScheduleKeyDeletion` event).
2. **Within the pending-delete window (7-30 days):** `aws kms cancel-key-deletion --key-id <id>`.
3. **Past the window:** ciphertext is permanently unrecoverable. There is no recovery. The only mitigation is to:
   - Mark all credentials `status = 'lost'` (manual schema addition; do not exist by default).
   - Notify all affected users to re-enter credentials.
   - This is a customer-facing incident.

**Prevention is the only real defense.** The deny-deletion key policy must be in place from day one.

### KMS regional outage

Per [ADR 0008](adr/0008-failure-modes.md): the KMS circuit breaker opens, cached DEKs continue to serve hot tenants with extended TTL (1 hour), cold reads return `UNAVAILABLE`. **No operator action needed during the outage** — the breaker closes automatically when KMS recovers.

If the outage exceeds the extended TTL (1 hour), the vault degrades to "no reads succeed for any tenant." The runbook entry is:
- Acknowledge the AWS Health Dashboard incident.
- Do not attempt failover to another region — the KEK is region-scoped; failover requires re-wrapping every DEK against a different-region key, which is a multi-hour data migration, not a runbook procedure.
- Communicate the dependency to stakeholders.

### KMS key compromise suspected

1. Disable the key immediately (`aws kms disable-key`). This makes ALL credentials unreadable — accept the outage.
2. Investigate the breach via CloudTrail and IAM access analyzer.
3. Generate a new KEK and run `coffer-migrate` to re-wrap every DEK against it.
4. Re-enable serving from the new key, retire the old.
5. Post-incident: investigate how the old KEK was reachable and harden IAM.

### Vault credentials (IAM access keys) compromised

The vault uses an IAM role for KMS access; access-key compromise is one layer of indirection above the KEK. Procedure:
1. Rotate IAM credentials immediately.
2. Inspect CloudTrail for `kms:Decrypt` calls outside the expected service signature.
3. If unauthorized Decrypts are found, treat as KEK compromise (above).

## Multi-region story (deferred)

KMS keys are region-scoped. Multi-region KMS keys exist (`--multi-region true`) but require a different replication strategy for the ciphertext, and are out of scope for the trial. Documented as future work in [PRD §8](PRD.md).

## Audit

- All KMS operations are CloudTrail-logged.
- Alert conditions:
  - Any `kms:ScheduleKeyDeletion` event for `alias/coffer-tenant-kek` — page immediately.
  - Any `kms:DisableKey` event — page immediately.
  - `kms:Decrypt` from an unexpected role — investigate.
  - >1% `Decrypt` failure rate for >5 minutes — page (matches `coffer_kms_breaker_state` alert from ADR 0009).
