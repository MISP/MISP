-- Patch to add column in servers table in order to save 'publish_without_email'

ALTER TABLE `servers` ADD `publish_without_email` tinyint(1) NOT NULL DEFAULT 0;
