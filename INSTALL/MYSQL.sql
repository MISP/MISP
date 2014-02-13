-- --------------------------------------------------------

--
-- Table structure for table `attributes`
--

CREATE TABLE IF NOT EXISTS `attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `category` varchar(255) COLLATE utf8_bin NOT NULL,
  `type` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `value1` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `value2` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT '1',
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT '0',
  `distribution` tinyint(4) NOT NULL DEFAULT '0',
  `comment` text COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `uuid` (`uuid`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `bruteforces`
--

CREATE TABLE IF NOT EXISTS `bruteforces` (
  `ip` varchar(255) COLLATE utf8_bin NOT NULL,
  `username` varchar(255) COLLATE utf8_bin NOT NULL,
  `expire` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `cake_sessions`
--

CREATE TABLE IF NOT EXISTS `cake_sessions` (
  `id` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  `data` text COLLATE utf8_bin NOT NULL,
  `expires` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `correlations`
--

CREATE TABLE IF NOT EXISTS `correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `1_event_id` int(11) NOT NULL,
  `1_attribute_id` int(11) NOT NULL,
  `1_private` tinyint(1) NOT NULL DEFAULT '0',
  `event_id` int(11) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `private` tinyint(1) NOT NULL,
  `date` date NOT NULL,
  `info` text COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`),
  KEY `1_event_id` (`1_event_id`),
  KEY `1_attribute_id` (`1_attribute_id`),
  KEY `attribute_id` (`attribute_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `events`
--

CREATE TABLE IF NOT EXISTS `events` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `date` date NOT NULL,
  `info` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `user_id` int(11) NOT NULL,
  `published` tinyint(1) NOT NULL DEFAULT '0',
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `attribute_count` int(11) NOT NULL,
  `analysis` tinyint(4) NOT NULL,
  `orgc` varchar(255) COLLATE utf8_bin NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT '0',
  `distribution` tinyint(4) NOT NULL DEFAULT '0',
  `proposal_email_lock` tinyint(1) NOT NULL DEFAULT '0',
  `locked` tinyint(1) NOT NULL DEFAULT '0',
  `threat_level_id` int(11) NOT NULL,
  `publish_timestamp` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  FULLTEXT KEY `info` (`info`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- -------------------------------------------------------

--
-- Table structure for `event_tags`
--

CREATE TABLE IF NOT EXISTS `event_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `jobs`
--

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

-- --------------------------------------------------------

--
-- Table structure for table `logs`
--

CREATE TABLE IF NOT EXISTS `logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  `created` datetime DEFAULT NULL,
  `model` varchar(20) COLLATE utf8_bin DEFAULT NULL,
  `model_id` int(11) DEFAULT NULL,
  `action` varchar(20) COLLATE utf8_bin DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `change` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  `email` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  `org` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  `description` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `posts`
--

CREATE TABLE IF NOT EXISTS `posts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `user_id` int(11) NOT NULL,
  `contents` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `post_id` int(11) NOT NULL DEFAULT '0',
  `thread_id` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ;

-- --------------------------------------------------------

--
-- Table structure for table `regexp`
--

CREATE TABLE IF NOT EXISTS `regexp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `regexp` varchar(255) COLLATE utf8_bin NOT NULL,
  `replacement` varchar(255) COLLATE utf8_bin NOT NULL,
  `type` varchar(100) COLLATE utf8_bin NOT NULL DEFAULT 'ALL',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `roles`
--

CREATE TABLE IF NOT EXISTS `roles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8_bin NOT NULL,
  `created` datetime DEFAULT NULL,
  `modified` datetime DEFAULT NULL,
  `perm_add` tinyint(1) DEFAULT NULL,
  `perm_modify` tinyint(1) DEFAULT NULL,
  `perm_modify_org` tinyint(1) DEFAULT NULL,
  `perm_publish` tinyint(1) DEFAULT NULL,
  `perm_sync` tinyint(1) DEFAULT NULL,
  `perm_admin` tinyint(1) DEFAULT NULL,
  `perm_audit` tinyint(1) DEFAULT NULL,
  `perm_full` tinyint(1) DEFAULT NULL,
  `perm_auth` tinyint(1) NOT NULL DEFAULT '0',
  `perm_site_admin` tinyint(1) NOT NULL DEFAULT '0',
  `perm_regexp_access` tinyint(1) NOT NULL DEFAULT '0',
  `perm_tagger` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `servers`
--

CREATE TABLE IF NOT EXISTS `servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) COLLATE utf8_bin NOT NULL,
  `authkey` varchar(40) COLLATE utf8_bin NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `organization` varchar(10) COLLATE utf8_bin NOT NULL,
  `push` tinyint(1) NOT NULL,
  `pull` tinyint(1) NOT NULL,
  `lastpulledid` int(11) NOT NULL,
  `lastpushedid` int(11) NOT NULL,
  `self_signed` tinyint(1) NOT NULL,
  `cert_file` varchar(255) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `shadow_attributes`
--

CREATE TABLE IF NOT EXISTS `shadow_attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `old_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `type` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `category` varchar(255) COLLATE utf8_bin NOT NULL,
  `value1` text COLLATE utf8_bin,
  `to_ids` tinyint(1) NOT NULL DEFAULT '1',
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `value2` text COLLATE utf8_bin,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `email` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `event_org` varchar(255) COLLATE utf8_bin NOT NULL,
  `comment` text COLLATE utf8_bin NOT NULL,
  `event_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `uuid` (`uuid`),
  KEY `old_id` (`old_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `tags`
--

CREATE TABLE IF NOT EXISTS `tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `colour` varchar(7) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
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


-- --------------------------------------------------------

--
-- Table structure for table `threads`
--

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
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 ;

-- --------------------------------------------------------

--
-- Table structure for table `threat_levels`
--

CREATE TABLE IF NOT EXISTS `threat_levels` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `form_description` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(40) COLLATE utf8_bin NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `email` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `autoalert` tinyint(1) NOT NULL,
  `authkey` varchar(40) COLLATE utf8_bin NOT NULL,
  `invited_by` int(11) NOT NULL,
  `gpgkey` longtext COLLATE utf8_bin NOT NULL,
  `nids_sid` int(15) NOT NULL,
  `termsaccepted` tinyint(1) NOT NULL,
  `newsread` date NOT NULL,
  `role_id` int(11) NOT NULL,
  `change_pw` tinyint(4) NOT NULL,
  `contactalert` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `email` (`email`),
  KEY `password` (`password`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin ;

-- --------------------------------------------------------

--
-- Table structure for table `whitelist`
--

CREATE TABLE IF NOT EXISTS `whitelist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Default values for initial installation
--

 INSERT INTO `regexp` (`id`, `regexp`, `replacement`, `type`) VALUES
 (1, '/.:.ProgramData./i', '%ALLUSERSPROFILE%\\\\', 'ALL'),
 (2, '/.:.Documents and Settings.All Users./i', '%ALLUSERSPROFILE%\\\\', 'ALL'),
 (3, '/.:.Program Files.Common Files./i', '%COMMONPROGRAMFILES%\\\\', 'ALL'),
 (4, '/.:.Program Files (x86).Common Files./i', '%COMMONPROGRAMFILES(x86)%\\\\', 'ALL'),
 (5, '/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i', '%TEMP%\\\\', 'ALL'),
 (6, '/.:.ProgramData./i', '%PROGRAMDATA%\\\\', 'ALL'),
 (7, '/.:.Program Files./i', '%PROGRAMFILES%\\\\', 'ALL'),
 (8, '/.:.Program Files (x86)./i', '%PROGRAMFILES(X86)%\\\\', 'ALL'),
 (9, '/.:.Users.Public./i', '%PUBLIC%\\\\', 'ALL'),
 (10, '/.:.Documents and Settings\\\\(.*?)\\\\Local Settings.Temp./i', '%TEMP%\\\\', 'ALL'),
 (11, '/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i', '%TEMP%\\\\', 'ALL'),
 (12, '/.:.Users\\\\(.*?)\\\\AppData.Local./i', '%LOCALAPPDATA%\\\\', 'ALL'),
 (13, '/.:.Users\\\\(.*?)\\\\AppData.Roaming./i', '%APPDATA%\\\\', 'ALL'),
 (14, '/.:.Users\\\\(.*?)\\\\Application Data./i', '%APPDATA%\\\\', 'ALL'),
 (15, '/.:.Windows\\\\(.*?)\\\\Application Data./i', '%APPDATA%\\\\', 'ALL'),
 (16, '/.:.Users\\\\(.*?)\\\\/i', '%USERPROFILE%\\\\', 'ALL'),
 (17, '/.:.DOCUME~1.\\\\(.*?)\\\\/i', '%USERPROFILE%\\\\', 'ALL'),
 (18, '/.:.Documents and Settings\\\\(.*?)\\\\/i', '%USERPROFILE%\\\\', 'ALL'),
 (19, '/.:.Windows./i', '%WINDIR%\\\\', 'ALL'),
 (20, '/.:.Windows./i', '%WINDIR%\\\\', 'ALL'),
 (21, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}/i', 'HKCU', 'ALL'),
 (22, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}/i', 'HKCU', 'ALL'),
 (23, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}/i', 'HKCU', 'ALL'),
 (24, '/.REGISTRY.MACHINE./i', 'HKLM\\\\', 'ALL'),
 (25, '/.Registry.Machine./i', 'HKLM\\\\', 'ALL'),
 (26, '/%USERPROFILE%.Application Data.Microsoft.UProof/i', '', 'ALL'),
 (27, '/%USERPROFILE%.Local Settings.History/i', '', 'ALL'),
 (28, '/%APPDATA%.Microsoft.UProof/i ', '', 'ALL'),
 (29, '/%LOCALAPPDATA%.Microsoft.Windows.Temporary Internet Files/i', '', 'ALL');

-- --------------------------------------------------------

--
-- Creating initial roles
--
-- 1. Admin - has full access
-- 2. Org Admin - read/write/publish/audit/admin/sync/auth/tagger
-- 3. User - User - Read / Write, no other permissions (default)
-- 4. Sync user - read/write/publish/sync/auth
-- 5. Automation user - read/write/publish/auth
-- 6. Read Only - read
--

INSERT INTO `roles` (`id` ,`name` ,`created` ,`modified` ,`perm_add` ,`perm_modify` ,`perm_modify_org` ,`perm_publish` ,`perm_sync` ,`perm_admin` ,`perm_audit` ,`perm_full` ,`perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`)
VALUES ('1', 'admin', NOW() , NOW() , '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1');

INSERT INTO `roles` (`id` ,`name` ,`created` ,`modified` ,`perm_add` ,`perm_modify` ,`perm_modify_org` ,`perm_publish` ,`perm_sync` ,`perm_admin` ,`perm_audit` ,`perm_full` ,`perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`)
VALUES ('2', 'Org Admin', NOW() , NOW() , '1', '1', '1' , '1', '1', '1', '1', '0' , '1', '0', '1', '0');

INSERT INTO `roles` (`id` ,`name` ,`created` ,`modified` ,`perm_add` ,`perm_modify` ,`perm_modify_org` ,`perm_publish` ,`perm_sync` ,`perm_admin` ,`perm_audit` ,`perm_full` ,`perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`)
VALUES ('3', 'User', NOW() , NOW() , '1', '1', '1' , '0' , '0' , '0' , '0' , '0' , '0', '0', '0', '0');

INSERT INTO `roles` 
(`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`)
VALUES ('4', 'Sync user', NOW(), NOW(), '1', '1', '1', '1', '1', '0', '0', '0', '1', '0', '0', '0');

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`)
VALUES ('5', 'Automation user', NOW(), NOW(), '1', '1', '1', '1', '0', '0', '0', '0', '1', '0', '0', '0');

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`)
VALUES ('6', 'Read Only', NOW(), NOW(), '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0');

-- --------------------------------------------------------

--
-- Initial threat levels
--


INSERT INTO `threat_levels` (`id`, `name`, `description`, `form_description`)
VALUES
  (1,'High','*high* means sophisticated APT malware or 0-day attack','Sophisticated APT malware or 0-day attack'),
  (2,'Medium','*medium* means APT malware','APT malware'),
  (3,'Low','*low* means mass-malware','Mass-malware'),
  (4,'Undefined','*undefined* no risk','No risk');

-- --------------------------------------------------------
