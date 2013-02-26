--
-- Update to attributes
--
ALTER TABLE `attributes` ADD `cluster` tinyint(1) NOT NULL;
ALTER TABLE `attributes` ADD `communitie` tinyint(1) NOT NULL;
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
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;
-- --------------------------------------------------------

--
-- Update servers
--

ALTER TABLE `servers`  DROP `logo`;
-- --------------------------------------------------------

--
-- Update users
--

ALTER TABLE `users` ADD `role_id` int(11) NOT NULL;
ALTER TABLE `users` ADD `change_pw` tinyint(1) NOT NULL;
-- --------------------------------------------------------
