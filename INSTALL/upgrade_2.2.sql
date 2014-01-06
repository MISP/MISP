ALTER TABLE  `roles` ADD  `perm_site_admin` TINYINT( 1 ) NOT NULL DEFAULT  '0',
ADD  `perm_regexp_access` TINYINT( 1 ) NOT NULL DEFAULT  '0';

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

CREATE TABLE IF NOT EXISTS `posts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `user_id` int(11) NOT NULL,
  `contents` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `post_id` int(11) NOT NULL DEFAULT '0',
  `thread_id` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 ;

ALTER TABLE  `attributes` ADD  `comment` TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL;
ALTER TABLE  `shadow_attributes` ADD  `event_org` VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL;
ALTER TABLE  `shadow_attributes` ADD  `comment` TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL;
