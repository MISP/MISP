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
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `bruteforces`
--

CREATE TABLE IF NOT EXISTS `bruteforces` (
  `ip` varchar(255) COLLATE utf8_bin NOT NULL,
  `username` varchar(255) COLLATE utf8_bin NOT NULL,
  `expire` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `cake_sessions`
--

CREATE TABLE IF NOT EXISTS `cake_sessions` (
  `id` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  `data` text COLLATE utf8_bin NOT NULL,
  `expires` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

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
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

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
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

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
  `perm_template` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `servers`
--

CREATE TABLE IF NOT EXISTS `servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) COLLATE utf8_bin NOT NULL,
  `authkey` varchar(40) COLLATE utf8_bin NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `organization` varchar(255) COLLATE utf8_bin NOT NULL,
  `push` tinyint(1) NOT NULL,
  `pull` tinyint(1) NOT NULL,
  `lastpulledid` int(11) NOT NULL,
  `lastpushedid` int(11) NOT NULL,
  `self_signed` tinyint(1) NOT NULL,
  `cert_file` varchar(255) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

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
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `timestamp` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `uuid` (`uuid`),
  KEY `old_id` (`old_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

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
-- Table structure for table `tasks`
--

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
-- Table structure for table `templates`
--

CREATE TABLE IF NOT EXISTS `templates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `description` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `org` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `share` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_elements`
--

CREATE TABLE IF NOT EXISTS `template_elements` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_id` int(11) NOT NULL,
  `position` int(11) NOT NULL,
  `element_definition` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_element_attributes`
--

CREATE TABLE IF NOT EXISTS `template_element_attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_element_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT '1',
  `category` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `complex` tinyint(1) NOT NULL,
  `type` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `mandatory` tinyint(1) NOT NULL,
  `batch` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_element_files`
--

CREATE TABLE IF NOT EXISTS `template_element_files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_element_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `category` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `malware` tinyint(1) NOT NULL,
  `mandatory` tinyint(1) NOT NULL,
  `batch` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_element_texts`
--

CREATE TABLE IF NOT EXISTS `template_element_texts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `template_element_id` int(11) NOT NULL,
  `text` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_tags`
--

CREATE TABLE IF NOT EXISTS `template_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
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
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin ;

-- --------------------------------------------------------

--
-- Table structure for table `whitelist`
--

CREATE TABLE IF NOT EXISTS `whitelist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

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


-- --------------------------------------------------------

--
-- Default templates
--

INSERT INTO `templates` (`id`, `name`, `description`, `org`, `share`) VALUES
(1, 'Phishing E-mail', 'Create a MISP event about a Phishing E-mail.', 'MISP', 1),
(2, 'Phishing E-mail with malicious attachment', 'A MISP event based on Spear-phishing containing a malicious attachment. This event can include anything from the description of the e-mail itself, the malicious attachment and its description as well as the results of the analysis done on the malicious f', 'MISP', 1),
(3, 'Malware Report', 'This is a template for a generic malware report. ', 'MISP', 1),
(4, 'Indicator List', 'A simple template for indicator lists.', 'MISP', 1);

INSERT INTO `template_elements` (`id`, `template_id`, `position`, `element_definition`) VALUES
(1, 1, 2, 'attribute'),
(2, 1, 3, 'attribute'),
(3, 1, 1, 'text'),
(4, 1, 4, 'attribute'),
(5, 1, 5, 'text'),
(6, 1, 6, 'attribute'),
(7, 1, 7, 'attribute'),
(8, 1, 8, 'attribute'),
(11, 2, 1, 'text'),
(12, 2, 2, 'attribute'),
(13, 2, 3, 'text'),
(14, 2, 4, 'file'),
(15, 2, 5, 'attribute'),
(16, 2, 10, 'text'),
(17, 2, 6, 'attribute'),
(18, 2, 7, 'attribute'),
(19, 2, 8, 'attribute'),
(20, 2, 9, 'attribute'),
(21, 2, 11, 'file'),
(22, 2, 12, 'attribute'),
(23, 2, 13, 'attribute'),
(24, 2, 14, 'attribute'),
(25, 2, 15, 'attribute'),
(26, 2, 16, 'attribute'),
(27, 2, 17, 'attribute'),
(28, 2, 18, 'attribute'),
(29, 3, 1, 'text'),
(30, 3, 2, 'file'),
(31, 3, 4, 'text'),
(32, 3, 9, 'text'),
(33, 3, 11, 'text'),
(34, 3, 10, 'attribute'),
(35, 3, 12, 'attribute'),
(36, 3, 3, 'attribute'),
(37, 3, 5, 'attribute'),
(38, 3, 6, 'attribute'),
(39, 3, 7, 'attribute'),
(40, 3, 8, 'file'),
(41, 3, 13, 'text'),
(42, 3, 14, 'attribute'),
(43, 3, 15, 'attribute'),
(44, 3, 16, 'attribute'),
(45, 4, 1, 'text'),
(46, 4, 2, 'attribute'),
(47, 4, 3, 'attribute');

INSERT INTO `template_element_attributes` (`id`, `template_element_id`, `name`, `description`, `to_ids`, `category`, `complex`, `type`, `mandatory`, `batch`) VALUES
(1, 1, 'From address', 'The source address from which the e-mail was sent.', 1, 'Payload delivery', 0, 'email-src', 1, 1),
(2, 2, 'Malicious url', 'The malicious url in the e-mail body.', 1, 'Payload delivery', 0, 'url', 1, 1),
(3, 4, 'E-mail subject', 'The subject line of the e-mail.', 0, 'Payload delivery', 0, 'email-subject', 1, 0),
(4, 6, 'Spoofed source address', 'If an e-mail address was spoofed, specify which.', 1, 'Payload delivery', 0, 'email-src', 0, 0),
(5, 7, 'Source IP', 'The source IP from which the e-mail was sent', 1, 'Payload delivery', 0, 'ip-src', 0, 1),
(6, 8, 'X-mailer header', 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 1, 'Payload delivery', 0, 'text', 0, 1),
(7, 12, 'From address', 'The source address from which the e-mail was sent', 1, 'Payload delivery', 0, 'email-src', 1, 1),
(8, 15, 'Spoofed From Address', 'The spoofed source address from which the e-mail appears to be sent.', 1, 'Payload delivery', 0, 'email-src', 0, 1),
(9, 17, 'E-mail Source IP', 'The IP address from which the e-mail was sent.', 1, 'Payload delivery', 0, 'ip-src', 0, 1),
(10, 18, 'X-mailer header', 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 1, 'Payload delivery', 0, 'text', 0, 0),
(11, 19, 'Malicious URL in the e-mail', 'If there was a malicious URL (or several), please specify it here', 1, 'Payload delivery', 0, 'ip-dst', 0, 1),
(12, 20, 'Exploited vulnerablity', 'The vulnerabilities exploited during the payload delivery.', 0, 'Payload delivery', 0, 'vulnerability', 0, 1),
(13, 22, 'C2 information', 'Command and Control information detected during the analysis.', 1, 'Network activity', 1, 'CnC', 0, 1),
(14, 23, 'Artifacts dropped (File)', 'Any information about the files dropped during the analysis', 1, 'Artifacts dropped', 1, 'File', 0, 1),
(15, 24, 'Artifacts dropped (Registry key)', 'Any registry keys touched during the analysis', 1, 'Artifacts dropped', 0, 'regkey', 0, 1),
(16, 25, 'Artifacts dropped (Registry key + value)', 'Any registry keys created or altered together with the value.', 1, 'Artifacts dropped', 0, 'regkey|value', 0, 1),
(17, 26, 'Persistance mechanism (filename)', 'Filenames (or filenames with filepaths) used as a persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey|value', 0, 1),
(18, 27, 'Persistence mechanism (Registry key)', 'Any registry keys touched as part of the persistence mechanism during the analysis ', 1, 'Persistence mechanism', 0, 'regkey', 0, 1),
(19, 28, 'Persistence mechanism (Registry key + value)', 'Any registry keys created or modified together with their values used by the persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey|value', 0, 1),
(20, 34, 'C2 Information', 'You can drop any urls, domains, hostnames or IP addresses that were detected as the Command and Control during the analysis here. ', 1, 'Network activity', 1, 'CnC', 0, 1),
(21, 35, 'Other Network Activity', 'Drop any applicable information about other network activity here. The attributes created here will NOT be marked for IDS exports.', 0, 'Network activity', 1, 'CnC', 0, 1),
(22, 36, 'Vulnerability', 'The vulnerability or vulnerabilities that the sample exploits', 0, 'Payload delivery', 0, 'vulnerability', 0, 1),
(23, 37, 'Artifacts Dropped (File)', 'Insert any data you have on dropped files here.', 1, 'Artifacts dropped', 1, 'File', 0, 1),
(24, 38, 'Artifacts dropped (Registry key)', 'Any registry keys touched during the analysis', 1, 'Artifacts dropped', 0, 'regkey', 0, 1),
(25, 39, 'Artifacts dropped (Registry key + value)', 'Any registry keys created or altered together with the value.', 1, 'Artifacts dropped', 0, 'regkey|value', 0, 1),
(26, 42, 'Persistence mechanism (filename)', 'Insert any filenames used by the persistence mechanism.', 1, 'Persistence mechanism', 0, 'filename', 0, 1),
(27, 43, 'Persistence Mechanism (Registry key)', 'Paste any registry keys that were created or modified as part of the persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey', 0, 1),
(28, 44, 'Persistence Mechanism (Registry key and value)', 'Paste any registry keys together with the values contained within created or modified by the persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey|value', 0, 1),
(29, 46, 'Network Indicators', 'Paste any combination of IP addresses, hostnames, domains or URL', 1, 'Network activity', 1, 'CnC', 0, 1),
(30, 47, 'File Indicators', 'Paste any file hashes that you have (MD5, SHA1, SHA256) or filenames below. You can also add filename and hash pairs by using the following syntax for each applicable column: filename|hash ', 1, 'Payload installation', 1, 'File', 0, 1);

INSERT INTO `template_element_files` (`id`, `template_element_id`, `name`, `description`, `category`, `malware`, `mandatory`, `batch`) VALUES
(1, 14, 'Malicious Attachment', 'The file (or files) that was (were) attached to the e-mail itself.', 'Payload delivery', 1, 0, 1),
(2, 21, 'Payload installation', 'Payload installation detected during the analysis', 'Payload installation', 1, 0, 1),
(3, 30, 'Malware sample', 'The sample that the report is based on', 'Payload delivery', 1, 0, 0),
(4, 40, 'Artifacts dropped (Sample)', 'Upload any files that were dropped during the analysis.', 'Artifacts dropped', 1, 0, 1);

INSERT INTO `template_element_texts` (`id`, `name`, `template_element_id`, `text`) VALUES
(1, 'Required fields', 3, 'The fields below are mandatory.'),
(2, 'Optional information', 5, 'All of the fields below are optional, please fill out anything that''s applicable.'),
(4, 'Required Fields', 11, 'The following fields are mandatory'),
(5, 'Optional information about the payload delivery', 13, 'All of the fields below are optional, please fill out anything that''s applicable. This section describes the payload delivery, including the e-mail itself, the attached file, the vulnerability it is exploiting and any malicious urls in the e-mail.'),
(6, 'Optional information obtained from analysing the malicious file', 16, 'Information about the analysis of the malware (if applicable). This can include C2 information, artifacts dropped during the analysis, persistance mechanism, etc.'),
(7, 'Malware Sample', 29, 'If you can, please upload the sample that the report revolves around.'),
(8, 'Dropped Artifacts', 31, 'Describe any dropped artifacts that you have encountered during your analysis'),
(9, 'C2 Information', 32, 'The following field deals with Command and Control information obtained during the analysis. All fields are optional.'),
(10, 'Other Network Activity', 33, 'If any other Network activity (such as an internet connection test) was detected during the analysis, please specify it using the following fields'),
(11, 'Persistence mechanism', 41, 'The following fields allow you to describe the persistence mechanism used by the malware'),
(12, 'Indicators', 45, 'Just paste your list of indicators based on type into the appropriate field. All of the fields are optional, so inputting a list of IP addresses into the Network indicator field for example is sufficient to complete this template.');

INSERT INTO `tasks` (`id`, `type`, `timer`, `scheduled_time`, `job_id`, `description`, `next_execution_time`, `message`) VALUES
(1, 'cache_exports', 0, '12:00', 0, 'Generates export caches for every export type and for every organisation. This process is heavy, schedule so it might be a good idea to schedule this outside of working hours and before your daily automatic imports on connected services are scheduled.', 1391601600, 'Not scheduled yet.'),
(2, 'pull_all', 0, '12:00', 0, 'Initiates a full pull for all eligible instances.', 1391601600, 'Not scheduled yet.'),
(3, 'push_all', 0, '12:00', 0, 'Initiates a full push for all eligible instances.', 1391601600, 'Not scheduled yet.');
