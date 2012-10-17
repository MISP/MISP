ALTER TABLE `events` ADD `cluster` tinyint(1) NOT NULL;
ALTER TABLE `attributes` ADD `cluster` tinyint(1) NOT NULL;

ALTER TABLE `correlations` ADD private tinyint(1) NOT NULL;
ALTER TABLE `correlations` ADD org varchar(255) COLLATE utf8_bin NOT NULL;