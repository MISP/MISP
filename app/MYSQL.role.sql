alter table roles add column perm_sync tinyint(1);

alter table roles add column perm_admin tinyint(1);
alter table roles add column perm_audit tinyint(1);
