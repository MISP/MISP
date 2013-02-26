 
ALTER TABLE `roles` ADD `perm_admin` TINYINT( 1 ) NOT NULL DEFAULT '0';
ALTER TABLE `roles` ADD `perm_audit` TINYINT( 1 ) NOT NULL DEFAULT '0';
 
INSERT INTO `roles` (
`id` ,
`name` ,
`created` ,
`modified` ,
`perm_add` ,
`perm_modify` ,
`perm_modify_org` ,
`perm_publish` ,
`perm_sync` ,
`perm_admin` ,
`perm_audit` ,
`perm_full` ,
`perm_auth`
)
VALUES (
'1', 'ADMIN', '2013-02-26 14:27:20', '2013-02-26 14:27:20', '1', '1', '1', '1', '1', '1', '1', '1', '1'
);