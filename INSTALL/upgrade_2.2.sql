-- Copyright (c) 2009 www.cryer.co.uk
-- Script is free to use provided this copyright header is included.
drop procedure if exists AddColumnUnlessExists;
delimiter '//'

create procedure AddColumnUnlessExists(
	IN dbName tinytext,
	IN tableName tinytext,
	IN fieldName tinytext,
	IN fieldDef text)
begin
	IF NOT EXISTS (
		SELECT * FROM information_schema.COLUMNS
		WHERE column_name=fieldName
		and table_name=tableName
		and table_schema=dbName
		)
	THEN
		set @ddl=CONCAT('ALTER TABLE ',dbName,'.',tableName,
			' ADD COLUMN ',fieldName,' ',fieldDef);
		prepare stmt from @ddl;
		execute stmt;
	END IF;
end;
//

delimiter ';'

call AddColumnUnlessExists(Database(), 'roles', 'perm_site_admin', 'TINYINT( 1 ) NOT NULL DEFAULT 0');
call AddColumnUnlessExists(Database(), 'roles', 'perm_regexp_access', 'TINYINT( 1 ) NOT NULL DEFAULT 0');
call AddColumnUnlessExists(Database(), 'roles', 'perm_tagger', 'TINYINT( 1 ) NOT NULL DEFAULT 0');

CREATE TABLE IF NOT EXISTS `threads` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `user_id` int(11) NOT NULL,
  `post_count` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `title` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `org` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `posts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `user_id` int(11) NOT NULL,
  `contents` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `post_id` int(11) NOT NULL DEFAULT '0',
  `thread_id` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;


CREATE TABLE IF NOT EXISTS `event_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `colour` varchar(7) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `threat_levels` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `form_description` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `tasks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `timer` int(11) NOT NULL,
  `scheduled_time` varchar(8) NOT NULL DEFAULT '6:00',
  `job_id` int(11) NOT NULL,
  `description` varchar(255) NOT NULL,
  `next_execution_time` int(11) NOT NULL,
  `message` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `jobs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `worker` varchar(32) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `job_type` varchar(32) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `job_input` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `status` tinyint(4) NOT NULL DEFAULT '0',
  `retries` int(11) NOT NULL DEFAULT '0',
  `message` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `progress` int(11) NOT NULL DEFAULT '0',
  `org` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `process_id` varchar(32) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;


call AddColumnUnlessExists(Database(), 'attributes', 'comment', 'TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL');

call AddColumnUnlessExists(Database(), 'events', 'threat_level_id', 'int(11) NOT NULL');
call AddColumnUnlessExists(Database(), 'events', 'publish_timestamp', 'int(11) NOT NULL');

call AddColumnUnlessExists(Database(), 'shadow_attributes', 'event_org', 'VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL');
call AddColumnUnlessExists(Database(), 'shadow_attributes', 'comment', 'TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL');
call AddColumnUnlessExists(Database(), 'shadow_attributes', 'event_uuid', 'varchar(40) COLLATE utf8_bin NOT NULL');

call AddColumnUnlessExists(Database(), 'servers', 'self_signed', ' tinyint(1) NOT NULL');
call AddColumnUnlessExists(Database(), 'servers', 'cert_file', 'varchar(255) COLLATE utf8_bin NOT NULL');

call AddColumnUnlessExists(Database(), 'regexp', 'type', 'COLLATE utf8_bin NOT NULL DEFAULT "ALL"');

drop procedure AddColumnUnlessExists;

UPDATE `regexp` SET `type` = 'ALL';

UPDATE `roles` SET `perm_site_admin` = 1 WHERE `id` = 1;
UPDATE `roles` SET `perm_tagger` = 1 WHERE `id` = 1;
UPDATE `roles` SET `perm_regexp_access` = 1 WHERE `id` = 1;

INSERT IGNORE INTO `threat_levels` (`id`, `name`, `description`, `form_description`)
VALUES
  (1,'High','*high* means sophisticated APT malware or 0-day attack','Sophisticated APT malware or 0-day attack'),
  (2,'Medium','*medium* means APT malware','APT malware'),
  (3,'Low','*low* means mass-malware','Mass-malware'),
  (4,'Undefined','*undefined* no risk','No risk');

INSERT IGNORE INTO `tasks` (`id`, `type`, `timer`, `scheduled_time`, `job_id`, `description`, `next_execution_time`, `message`) VALUES
(1, 'cache_exports', 0, '12:00', 0, 'Generates export caches for every export type and for every organisation. This process is heavy, schedule so it might be a good idea to schedule this outside of working hours and before your daily automatic imports on connected services are scheduled.', 1391601600, 'Not scheduled yet.'),
(2, 'pull_all', 0, '12:00', 0, 'Initiates a full pull for all eligible instances.', 1391601600, 'Not scheduled yet.'),
(3, 'push_all', 0, '12:00', 0, 'Initiates a full push for all eligible instances.', 1391601600, 'Not scheduled yet.');

