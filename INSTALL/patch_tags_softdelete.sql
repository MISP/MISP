-- Patch to add column in attribute_tags and event_tags

ALTER TABLE `attribute_tags` ADD `deleted` tinyint(1) NOT NULL DEFAULT 0;
ALTER TABLE `event_tags` ADD `deleted` tinyint(1) NOT NULL DEFAULT 0;

