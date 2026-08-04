-- Patch to add column in users table in order to save x509 certificate

ALTER TABLE `users` ADD `certif_public` longtext COLLATE utf8_bin NOT NULL AFTER `gpgkey`;
