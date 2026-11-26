# Upgrading MISP

!!! note
    As time goes by this space will be populated with certain upgrade specific tasks that might at the time of this writing still be in the [MISP-book](https://www.circl.lu/doc/misp/)

!!! warning
    If you are a MISP developer reading this.<br />
    Always aim to avoid having to write anything about a specific upgrade procedure. We strive to make our upgrades as seamless as possible and no extra steps should be needed, alas, extreme circumstances sometimes need those extreme measures.<br />
    We have been warned.

## Schema monitoring after the migration ledger

!!! warning
    If you monitor your instances through the schema diagnostic (`/servers/dbSchemaDiagnostic`, the payload fleet checks poll), your alert rule needs changing. Do it together with the upgrade, not after.

MISP now records schema changes in a `schema_migrations` ledger, one row per
migration, instead of advancing the `db_version` counter. `db_version` is frozen
at 159 permanently. The consequence for monitoring:

- **`actual_db_version` vs `expected_db_version` no longer detects anything.**
  Both are 159 on every instance from now on, including one that has unapplied
  or failed migrations. The comparison is not wrong; it is constant.
- **Alert on `migrations_pending > 0` instead.** This is the direct replacement.
  `migrations_pending_ids` names the migrations the instance is behind on, so
  the alert body can say which.
- **Alert on `migrations_failed > 0` as well.** This is new: a failed migration
  now halts the update run, everything behind it stays pending, and the failure
  is recorded (`migrations_failed_ids`). The previous system could not report
  this state at all — a later update would advance the version past the failure
  and the instance looked healthy.
- `update_locked`, `remaining_lock_time` and `update_fail_number_reached` keep
  their meaning.

The diagnostics page shows the same figures, and so does
`Console/cake Admin schemaDiagnostics`. The full description of the fields and
of what a halted instance looks like is in
[docs/dev/database-migrations.md](dev/database-migrations.md), section 11.
