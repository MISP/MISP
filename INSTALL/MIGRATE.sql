-- --------------------------------------------------------

--
-- Remove the tables used for the old ACL
--
DROP TABLE `aros`;
DROP TABLE `acos`;
DROP TABLE `aros_acos`;

-- --------------------------------------------------------

--
-- Alter the attributes table and set the new distribution + timestamp
--

ALTER TABLE `attributes` ADD  `timestamp` INT NOT NULL DEFAULT  '0';
ALTER TABLE `attributes` ADD  `distribution` tinyint(4) NOT NULL DEFAULT '0';
UPDATE `attributes` SET `distribution` = '0' WHERE `private` = '1' AND `cluster` = '0';
UPDATE `attributes` SET `distribution` = '1' WHERE `cluster` = '1';
UPDATE `attributes` SET `distribution` = '2' WHERE `communitie` = '1';
UPDATE `attributes` SET `distribution` = '3' WHERE `private` = '0' AND `cluster` = '0' AND `communitie` = '0';
UPDATE `attributes` SET `timestamp` = '1000000000' WHERE `timestamp` = '0';
ALTER TABLE `attributes` DROP `dist_change`;
ALTER TABLE `attributes` DROP `private`;
ALTER TABLE `attributes` DROP `cluster`;
ALTER TABLE `attributes` DROP `communitie`;
ALTER TABLE `attributes` DROP `revision`;

-- --------------------------------------------------------

--
-- Alter the events table and set the new distribution + timestamp
--

ALTER TABLE `events` ADD `timestamp` INT NOT NULL DEFAULT  '0';
ALTER TABLE `events` ADD `distribution` tinyint(4) NOT NULL DEFAULT '0';
ALTER TABLE `events` ADD `proposal_email_lock` tinyint(1) NOT NULL DEFAULT '0';
UPDATE `events` SET `distribution` = '0' WHERE `private` = '1' AND `cluster` = '0';
UPDATE `events` SET `distribution` = '1' WHERE `cluster` = '1';
UPDATE `events` SET `distribution` = '2' WHERE `communitie` = '1';
UPDATE `events` SET `distribution` = '3' WHERE `private` = '0' AND `cluster` = '0' AND `communitie` = '0';
UPDATE `events` SET `timestamp` = '1000000000' WHERE `timestamp` = '0';
ALTER TABLE `events` DROP `dist_change`;
ALTER TABLE `events` DROP `private`;
ALTER TABLE `events` DROP `cluster`;
ALTER TABLE `events` DROP `communitie`;
ALTER TABLE `events` DROP `revision`;
ALTER TABLE `events` DROP `hop_count`;

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