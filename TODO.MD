DB changes:

`alter table audit_logs rename column `change` to `changed`;`
`alter table audit_logs rename column `action` to `request_action`;`



Other changes:

change ID fields to bigint for tables where we expect extremely large data sets and/or growing ID spaces (correlations, logs)