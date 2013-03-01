--
-- Update to attributes
--

ALTER TABLE `attributes` ADD `cluster` tinyint(1) DEFAULT '0';
ALTER TABLE `attributes` ADD `communitie` tinyint(1) DEFAULT '0';
ALTER TABLE `attributes` ADD `dist_change` int(11) DEFAULT '0';
-- --------------------------------------------------------

--
-- Create blacklist
--  
  
CREATE TABLE `blacklist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(254) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;
-- --------------------------------------------------------

--
-- Create correlations
--

DROP TABLE IF EXISTS `correlations`;
CREATE TABLE `correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `1_event_id` int(11) NOT NULL,
  `1_attribute_id` int(11) NOT NULL,
  `1_private` tinyint(1) NOT NULL,
  `event_id` int(11) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `private` tinyint(1) NOT NULL,
  `cluster` tinyint(1) NOT NULL,
  `date` date NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=118 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
-- --------------------------------------------------------

--
-- Update to events
--

ALTER TABLE `events` ADD `cluster` tinyint(1) NOT NULL;
ALTER TABLE `events` ADD `communitie` tinyint(1) NOT NULL;
ALTER TABLE `events` ADD `analysis` tinyint(4) NOT NULL;
ALTER TABLE `events` ADD `attribute_count` int(11) UNSIGNED DEFAULT NULL;
ALTER TABLE `events` ADD `hop_count` int(11) UNSIGNED DEFAULT NULL;
ALTER TABLE `events` ADD `dist_change` int(11) NOT NULL DEFAULT 0;
ALTER TABLE `events` ADD `orgc` VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL;
UPDATE TABLE `events` SET `orgc` = `org` WHERE `orgc` = NULL;  
-- --------------------------------------------------------

--
-- Table structure for table `logs`
--

CREATE TABLE `logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(255) COLLATE utf8_bin NOT NULL,
  `created` datetime NOT NULL,
  `model` varchar(20) COLLATE utf8_bin NOT NULL,
  `model_id` int(11) NOT NULL,
  `action` varchar(20) COLLATE utf8_bin NOT NULL,
  `user_id` int(11) NOT NULL,
  `change` varchar(255) COLLATE utf8_bin,
  `email` varchar(255) COLLATE utf8_bin NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `description` varchar(255) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;
-- --------------------------------------------------------

--
-- Table structure for table `regexp`
--

CREATE TABLE `regexp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `regexp` varchar(255) COLLATE utf8_bin NOT NULL,
  `replacement` varchar(255) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=16 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
-- --------------------------------------------------------

--
-- Create table roles
--

DROP TABLE IF EXISTS `roles`;
CREATE TABLE `roles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8_bin NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `perm_add` tinyint(1) NOT NULL,
  `perm_modify` tinyint(1) NOT NULL,
  `perm_modify_org` tinyint(1) NOT NULL,
  `perm_publish` tinyint(1) NOT NULL,
  `perm_sync` tinyint(1) NOT NULL,
  `perm_full` tinyint(1) NOT NULL,
  `perm_auth` tinyint(1) NOT NULL,
  `perm_audit` tinyint(1) NOT NULL,
  `perm_admin` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;
-- --------------------------------------------------------

--
-- Creating initial roles
--
-- 1. Admin - has full access
-- 2. Org Admin - read/write/publish/audit/admin/sync/auth
-- 3. User - User - Read / Write, no other permissions (default)
-- 4. Sync user - read/write/publish/sync/auth
--

INSERT INTO `roles` (`id` ,`name` ,`created` ,`modified` ,`perm_add` ,`perm_modify` ,`perm_modify_org` ,`perm_publish` ,`perm_sync` ,`perm_admin` ,`perm_audit` ,`perm_full` ,`perm_auth`)
VALUES ('1', 'admin', NOW() , NOW() , '1', '1', '1', '1', '1', '1', '1', '1', '1');

INSERT INTO `roles` (`id` ,`name` ,`created` ,`modified` ,`perm_add` ,`perm_modify` ,`perm_modify_org` ,`perm_publish` ,`perm_sync` ,`perm_admin` ,`perm_audit` ,`perm_full` ,`perm_auth`)
VALUES ('2', 'Org Admin', NOW() , NOW() , '1', '1', '0' , '1', '1', '1', '1', '0' , '1');

INSERT INTO `roles` (`id` ,`name` ,`created` ,`modified` ,`perm_add` ,`perm_modify` ,`perm_modify_org` ,`perm_publish` ,`perm_sync` ,`perm_admin` ,`perm_audit` ,`perm_full` ,`perm_auth`)
VALUES ('3', 'User', NOW() , NOW() , '1', '1', '0' , '0' , '0' , '0' , '0' , '0' , '0');

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`)
VALUES ('4', 'Sync user', NOW(), NOW(), '1', '1', '1', '1', '1', '0', '1', '0', '1');
-- --------------------------------------------------------

--
-- Update servers
--

ALTER TABLE `servers` DROP `logo`;
-- --------------------------------------------------------

--
-- Update users
-- Collate changed for email - fixes case sensitivity of user names
--

ALTER TABLE `users` ADD `role_id` int(11) NOT NULL;
ALTER TABLE `users` ADD `change_pw` tinyint(1) NOT NULL;
ALTER TABLE `users` CHANGE `email` `email` VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL 
UPDATE TABLE `users` SET `role_id` = '3';
UPDATE TABLE `users` SET `role_id` = '1' WHERE `org` = 'ADMIN';  
-- --------------------------------------------------------
