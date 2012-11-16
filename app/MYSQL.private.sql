ALTER TABLE `events` ADD `cluster` tinyint(1) NOT NULL;
ALTER TABLE `attributes` ADD `cluster` tinyint(1) NOT NULL;

ALTER TABLE `events` ADD `pull` tinyint(1) NOT NULL;
ALTER TABLE `attributes` ADD `pull` tinyint(1) NOT NULL;

ALTER TABLE `correlations` ADD private tinyint(1) NOT NULL;
ALTER TABLE `correlations` ADD org varchar(255) COLLATE utf8_bin NOT NULL;

ALTER TABLE `events` ADD `communitie` tinyint(1) NOT NULL;
ALTER TABLE `attributes` ADD `communitie` tinyint(1) NOT NULL;
