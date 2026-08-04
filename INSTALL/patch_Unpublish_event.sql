-- Patch to add column in servers table in order to save 'unpublish_event'

ALTER TABLE `servers` ADD `unpublish_event` tinyint(1) NOT NULL DEFAULT 0;
