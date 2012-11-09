DROP TABLE IF EXISTS `correlations`;
CREATE TABLE `correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `1_event_id` int(11) NOT NULL,
  `1_attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `org` varchar(255) COLLATE utf8_bin NOT NULL,
  `private` tinyint(1) NOT NULL,
  `cluster` tinyint(1) NOT NULL,
  `date` date NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=118 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- ALTER TABLE `correlations` ADD private tinyint(1) NOT NULL;
-- ALTER TABLE `correlations` ADD org varchar(255) COLLATE utf8_bin NOT NULL;