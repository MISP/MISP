-- --------------------------------------------------------

--
-- Table structure for table `attributes`
--

CREATE TABLE IF NOT EXISTS `attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `type` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `category` varchar(255) COLLATE utf8_bin NOT NULL,
  `value1` text COLLATE utf8_bin,
  `to_ids` tinyint(1) NOT NULL DEFAULT '1',
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `revision` int(10) NOT NULL DEFAULT '0',
  `value2` text COLLATE utf8_bin,
  `dist_change` int(11) NOT NULL DEFAULT '0',
  `timestamp` int(11) NOT NULL DEFAULT '0',
  `distribution` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `uuid` (`uuid`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin

-- --------------------------------------------------------

--
-- Table structure for table `blacklist`
--

CREATE TABLE IF NOT EXISTS `blacklist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(254) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
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
-- Table structure for table `correlations`
--

CREATE TABLE `correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text COLLATE utf8_bin NOT NULL,
  `1_event_id` int(11) NOT NULL,
  `1_attribute_id` int(11) NOT NULL,
  `1_private` tinyint(1) NOT NULL DEFAULT '0',
  `event_id` int(11) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `private` tinyint(1) NOT NULL,
  `date` date NOT NULL,
  `info` text COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
-- --------------------------------------------------------

--
-- Table structure for table `events`
--

CREATE TABLE IF NOT EXISTS `events` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `date` date NOT NULL,
  `risk` enum('Undefined','Low','Medium','High') COLLATE utf8_bin NOT NULL,
  `info` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `user_id` int(11) NOT NULL,
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `revision` tinyint(1) NOT NULL,
  `attribute_count` int(11) NOT NULL,
  `hop_count` int(11) NOT NULL DEFAULT '0',
  `published` tinyint(1) NOT NULL DEFAULT '0',
  `analysis` tinyint(4) NOT NULL,
  `orgc` varchar(255) COLLATE utf8_bin NOT NULL,
  `dist_change` int(11) NOT NULL DEFAULT '0',
  `timestamp` int(11) NOT NULL DEFAULT '0',
  `distribution` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  FULLTEXT KEY `info` (`info`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin

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
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `regexp`
--

CREATE TABLE IF NOT EXISTS `regexp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `regexp` varchar(255) COLLATE utf8_bin NOT NULL,
  `replacement` varchar(255) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `roles`
--

CREATE TABLE IF NOT EXISTS `roles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
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
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1;

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
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `uuid` (`uuid`),
  KEY `old_id` (`old_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=11 ;
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
  `role_id` int(11) DEFAULT NULL,
  `change_pw` tinyint(4) NOT NULL,
  `contactalert` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `username` (`password`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `whitelist`
--

CREATE TABLE IF NOT EXISTS `whitelist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Default values for initial installation
--

INSERT INTO `regexp` 
  (`regexp`, `replacement`)
VALUES 
  ('/.:.ProgramData./i','%ALLUSERSPROFILE%\\\\'),
  ('/.:.Documents and Settings.All Users./i','%ALLUSERSPROFILE%\\\\'),
  ('/.:.Program Files.Common Files./i','%COMMONPROGRAMFILES%\\\\'),
  ('/.:.Program Files \(x86\).Common Files./i','%COMMONPROGRAMFILES(x86)%\\\\'),
  ('/.:.Users.(\\w+).AppData.Local.Temp./i','%TEMP%\\\\'),
  ('/.:.ProgramData./i','%PROGRAMDATA%\\\\'),
  ('/.:.Program Files./i','%PROGRAMFILES%\\\\'),
  ('/.:.Program Files \(x86\)./i','%PROGRAMFILES(X86)%\\\\'),
  ('/.:.Users.Public./i','%PUBLIC%\\\\'),
  ('/.:.Documents and Settings.(\\w+).Local Settings.Temp./i','%TEMP%\\\\'),
  ('/.:.Users.(\\w+).AppData.Local.Temp./i','%TEMP%\\\\'),
  ('/.:.Users.(\\w+).AppData.Local./i','%LOCALAPPDATA%\\\\'),
  ('/.:.Users.(\\w+).AppData.Roaming./i','%APPDATA%\\\\'),
  ('/.:.Users.(\\w+).Application Data./i','%APPDATA%\\\\'),
  ('/.:.Windows.(\\w+).Application Data./i','%APPDATA%\\\\'),
  ('/.:.Users.(\\w+)./i','%USERPROFILE%\\\\'),
  ('/.:.DOCUME~1.(\\w+)./i','%USERPROFILE%\\\\'),
  ('/.:.Documents and Settings.(\\w+)./i','%USERPROFILE%\\\\'),
  ('/.:.Windows./i','%WINDIR%\\\\'),
  ('/.:.Windows./i','%WINDIR%\\\\'),
  ('/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}/i','HKCU'),
  ('/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}/i','HKCU'),
  ('/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}/i','HKCU'),
  ('/.REGISTRY.MACHINE./i','HKLM\\\\'),
  ('/.Registry.Machine./i','HKLM\\\\');

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
VALUES ('2', 'Org Admin', NOW() , NOW() , '1', '1', '1' , '1', '1', '1', '1', '0' , '1');

INSERT INTO `roles` (`id` ,`name` ,`created` ,`modified` ,`perm_add` ,`perm_modify` ,`perm_modify_org` ,`perm_publish` ,`perm_sync` ,`perm_admin` ,`perm_audit` ,`perm_full` ,`perm_auth`)
VALUES ('3', 'User', NOW() , NOW() , '1', '1', '1' , '0' , '0' , '0' , '0' , '0' , '0');

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`)
VALUES ('4', 'Sync user', NOW(), NOW(), '1', '1', '1', '1', '1', '0', '1', '0', '1');

-- --------------------------------------------------------