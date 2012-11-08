-- ALTER TABLE `groups` drop modify_org;
ALTER TABLE `groups` ADD `perm_modify_org` tinyint(1) NOT NULL;
