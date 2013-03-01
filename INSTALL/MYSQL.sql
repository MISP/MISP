-- phpMyAdmin SQL Dump
-- version 3.3.9.2
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Jun 14, 2012 at 09:57 AM
-- Server version: 5.5.9
-- PHP Version: 5.3.6

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";

--
-- Database: `cydefsig`
--

-- --------------------------------------------------------

--
-- Table structure for table `attributes`
--

CREATE TABLE `attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `category` varchar(255) COLLATE utf8_bin NOT NULL,
  `type` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `value1` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `value2` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT '1',
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `revision` int(10) NOT NULL DEFAULT '0',
  `private` tinyint(1) NOT NULL,
  `cluster` tinyint(1) NOT NULL,
  `communitie` tinyint(1) NOT NULL,
  `dist_change` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `value1_key` (`value1`(5)),
  KEY `value2_key` (`value2`(5))
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `blacklist`
--

CREATE TABLE `blacklist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(254) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `bruteforces`
--

CREATE TABLE `bruteforces` (
  `ip` varchar(255) COLLATE utf8_bin NOT NULL,
  `username` varchar(255) COLLATE utf8_bin NOT NULL,
  `expire` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `correlations`
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
-- Table structure for table `events`
--

CREATE TABLE `events` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `date` date NOT NULL,
  `risk` enum('Undefined','Low','Medium','High') COLLATE utf8_bin NOT NULL,
  `info` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `user_id` int(11) NOT NULL,
  `published` tinyint(1) NOT NULL DEFAULT '0',
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `revision` int(10) NOT NULL DEFAULT '0',
  `private` tinyint(1) NOT NULL,
  `cluster` tinyint(1) NOT NULL,
  `analysis` tinyint(4) NOT NULL,
  `communitie` tinyint(1) NOT NULL,
  `attribute_count` int(11) UNSIGNED DEFAULT NULL,
  `hop_count` int(11) UNSIGNED DEFAULT 0,
  `dist_change` int(11) NOT NULL DEFAULT '0'
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `roles`
--

CREATE TABLE `roles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8_bin NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `perm_add` tinyint(1) NOT NULL DEFAULT 0,
  `perm_modify` tinyint(1) NOT NULL DEFAULT 0,
  `perm_modify_org` tinyint(1) NOT NULL DEFAULT 0,
  `perm_publish` tinyint(1) NOT NULL DEFAULT 0,
  `perm_sync` tinyint(1) NOT NULL DEFAULT 0,
  `perm_full` tinyint(1) NOT NULL DEFAULT 0,
  `perm_audit` tinyint(1) NOT NULL DEFAULT 0,
  `perm_admin` tinyint(1) NOT NULL DEFAULT 0,
  `perm_auth` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

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
-- Table structure for table `servers`
--

CREATE TABLE `servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) COLLATE utf8_bin NOT NULL,
  `authkey` varchar(40) COLLATE utf8_bin NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `organization` varchar(10) COLLATE utf8_bin NOT NULL,
  `push` tinyint(1) NOT NULL,
  `pull` tinyint(1) NOT NULL,
  `lastpushedid` int(11) NOT NULL,
  `lastpulledid` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(40) COLLATE utf8_bin NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `email` varchar(255) COLLATE utf8_bin NOT NULL,
  `autoalert` tinyint(1) NOT NULL,
  `authkey` varchar(40) COLLATE utf8_bin NOT NULL,
  `invited_by` int(11) NOT NULL,
  `gpgkey` longtext COLLATE utf8_bin NOT NULL,
  `nids_sid` int(15) NOT NULL,
  `termsaccepted` tinyint(1) NOT NULL,
  `change_pw` tinyint(1) NOT NULL,
  `newsread` date NOT NULL,
  `role_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `email` (`email`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=2 ;

-- --------------------------------------------------------

--
-- Table structure for table `whitelist`
--

CREATE TABLE `whitelist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(254) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;


--
-- Dumping data for table `attributes`
--

-- Dumping data for table `users`
--

INSERT INTO `users` (`id`,  `password`, `org`, `email`, `autoalert`, `authkey`, `invited_by`, `gpgkey`, `nids_sid`, `termsaccepted`, `newsread`, `role_id`) VALUES(1, 'babc86e0869015b3f0b4d48ca48700d3a9d1b9d7', 'ADMIN', 'admin@admin.test', 0, 'vlf4o42bYSVVWLm28jLB85my4HBZWXTri8vGdySb', 1, '', 4000000, 0, '2012-03-13', '');
INSERT INTO `regexp` (`id`,  `regexp`, `replacement`) VALUES (1,'/C:.Users.(\\w+).AppData.Local.Temp./','%TEMP%\\\\'),(3,'/C:.Users.(\\w+).AppData.Local./','%LOCALAPPDATA%\\\\'),(4,'/C:.Users.(\\w+).AppData.Roaming./','%APPDATA%\\\\'),(5,'/C:.Users.(\\w+)./','%UserProfile%\\\\'),(6,'/C:.Documents and Settings.(\\w+) (\\w+)./','%UserProfile%\\\\'),(7,'/C:.DOCUME~1.(\\w+)./','%UserProfile%\\\\'),(8,'/C:.Documents and Settings.All Users/','%AllUsersProfile%'),(9,'/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}/','HKCU'),(10,'@.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}@','HKCU'),(11,'@.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}@','HKCU'),(13,'@.REGISTRY.MACHINE.@','HKLM\\\\'),(14,'@.Registry.Machine.@','HKLM\\\\'),(15,'','not allowed'),(16,'/not allowed/',''),(26,'/%AppData\\\\\\\\/','%AppData%'),(27,'/%APPDATA%/','%AppData%'),(20,'','replacements to uniform the data'),(25,'/%allusers%/','%AllUsers%'),(28,'/%APPDATA%/','%AppData%'),(29,'/%LocalSettings&\\\\\\\\/','%LocalSettings%'),(30,'/%Programfiles%/','%ProgramFiles%'),(31,'/%systemroot%/','%SystemRoot%'),(32,'/%Temp\\\\\\\\/','%TEMP%'),(33,'/%Temp%/','%TEMP%'),(34,'/%temp%/','%TEMP%'),(35,'/%UserProfile\\\\\\\\/','%UserProfile%'),(36,'/%userprofile%/','%UserProfile%'),(37,'/%Windir%/','%windir%'),(38,'/%WINDIR%/','%windir%');
