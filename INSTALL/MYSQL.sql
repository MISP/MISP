-- --------------------------------------------------------

--
-- Table structure for table `admin_settings`
--

CREATE TABLE IF NOT EXISTS `admin_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `setting` varchar(255) COLLATE utf8_bin NOT NULL,
  `value` text COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `attributes`
--

CREATE TABLE IF NOT EXISTS `attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `object_id` int(11) NOT NULL DEFAULT 0,
  `object_relation` varchar(255) COLLATE utf8_bin,
  `category` varchar(255) COLLATE utf8_bin NOT NULL,
  `type` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `value1` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `value2` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT 1,
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) NOT NULL,
  `comment` text COLLATE utf8_bin,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `event_id` (`event_id`),
  INDEX `object_id` (`object_id`),
  INDEX `object_relation` (`object_relation`),
  INDEX `value1` (`value1`(255)),
  INDEX `value2` (`value2`(255)),
  INDEX `type` (`type`),
  INDEX `category` (`category`),
  INDEX `sharing_group_id` (`sharing_group_id`),
  UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- -------------------------------------------------------

--
-- Table structure for table `attribute_tags`
--

CREATE TABLE IF NOT EXISTS `attribute_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `attribute_id` (`attribute_id`),
  INDEX `event_id` (`event_id`),
  INDEX `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `bruteforces`
--

CREATE TABLE IF NOT EXISTS `bruteforces` (
  `ip` varchar(255) COLLATE utf8_bin NOT NULL,
  `username` varchar(255) COLLATE utf8_bin NOT NULL,
  `expire` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `cake_sessions`
--

CREATE TABLE IF NOT EXISTS `cake_sessions` (
  `id` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  `data` text COLLATE utf8_bin NOT NULL,
  `expires` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `correlations`
--

CREATE TABLE IF NOT EXISTS `correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text COLLATE utf8_bin NOT NULL,
  `1_event_id` int(11) NOT NULL,
  `1_attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `a_distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(11) NOT NULL,
  `a_sharing_group_id` int(11) NOT NULL,
  `date` date NOT NULL,
  `info` text COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `value` (`value`(255)),
  INDEX `event_id` (`event_id`),
  INDEX `1_event_id` (`1_event_id`),
  INDEX `attribute_id` (`attribute_id`),
  INDEX `1_attribute_id` (`1_attribute_id`),
  INDEX `org_id` (`org_id`),
  INDEX `sharing_group_id` (`sharing_group_id`),
  INDEX `a_sharing_group_id` (`a_sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `events`
--

CREATE TABLE IF NOT EXISTS `events` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `date` date NOT NULL,
  `info` text COLLATE utf8_bin NOT NULL,
  `user_id` int(11) NOT NULL,
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `published` tinyint(1) NOT NULL DEFAULT 0,
  `analysis` tinyint(4) NOT NULL,
  `attribute_count` int(11) unsigned DEFAULT 0,
  `orgc_id` int(11) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) NOT NULL,
  `proposal_email_lock` tinyint(1) NOT NULL DEFAULT 0,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `threat_level_id` int(11) NOT NULL,
  `publish_timestamp` int(11) NOT NULL DEFAULT 0,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  `extends_uuid` varchar(40) COLLATE utf8_bin DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `uuid` (`uuid`),
  INDEX `info` (`info`(255)),
  INDEX `sharing_group_id` (`sharing_group_id`),
  INDEX `org_id` (`org_id`),
  INDEX `orgc_id` (`orgc_id`),
  INDEX `extends_uuid` (`extends_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- -------------------------------------------------------

--
-- Table structure for `event_blacklists`
--

CREATE TABLE IF NOT EXISTS `event_blacklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `created` datetime NOT NULL,
  `event_info` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `event_orgc` VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `event_uuid` (`event_uuid`),
  INDEX `event_orgc` (`event_orgc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- -------------------------------------------------------

--
-- Table structure for `event_locks`
--

CREATE TABLE IF NOT EXISTS event_locks (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  INDEX `event_id` (`event_id`),
  INDEX `user_id` (`user_id`),
  INDEX `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- -------------------------------------------------------

--
-- Table structure for `event_delegations`
--

CREATE TABLE IF NOT EXISTS `event_delegations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `requester_org_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `message` text,
  `distribution` tinyint(4) NOT NULL DEFAULT -1,
  `sharing_group_id` int(11),
  PRIMARY KEY (`id`),
  INDEX `org_id` (`org_id`),
  INDEX `event_id` (`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- -------------------------------------------------------

--
-- Table structure for `event_tags`
--

CREATE TABLE IF NOT EXISTS `event_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `event_id` (`event_id`),
  INDEX `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- -------------------------------------------------------

--
-- Table structure for `favourite_tags`
--

CREATE TABLE IF NOT EXISTS `favourite_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tag_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `user_id` (`user_id`),
  INDEX `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- -------------------------------------------------------

--
-- Table structure for `feeds`
--

CREATE TABLE IF NOT EXISTS `feeds` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8_bin NOT NULL,
  `provider` varchar(255) COLLATE utf8_bin NOT NULL,
  `url` varchar(255) COLLATE utf8_bin NOT NULL,
  `rules` text COLLATE utf8_bin DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) NOT NULL DEFAULT 0,
  `tag_id` int(11) NOT NULL DEFAULT 0,
  `default` tinyint(1) DEFAULT 0,
  `source_format` varchar(255) COLLATE utf8_bin DEFAULT 'misp',
  `fixed_event` tinyint(1) NOT NULL DEFAULT 0,
  `delta_merge` tinyint(1) NOT NULL DEFAULT 0,
  `event_id` int(11) NOT NULL DEFAULT 0,
  `publish` tinyint(1) NOT NULL DEFAULT 0,
  `override_ids` tinyint(1) NOT NULL DEFAULT 0,
  `settings` text,
  `input_source` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT "network",
  `delete_local_file` tinyint(1) DEFAULT 0,
  `lookup_visible` tinyint(1) DEFAULT 0,
  `headers` TEXT COLLATE utf8_bin,
  `caching_enabled` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `input_source` (`input_source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- -------------------------------------------------------

--
-- Table structure for `fuzzy_correlate_ssdeep`
--

CREATE TABLE IF NOT EXISTS `fuzzy_correlate_ssdeep` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `chunk` varchar(12) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `chunk` (`chunk`),
  INDEX `attribute_id` (`attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- -------------------------------------------------------

--
-- Table structure for `galaxies`
--

CREATE TABLE IF NOT EXISTS galaxies (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) COLLATE utf8_bin NOT NULL,
  `name` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  `type` varchar(255) COLLATE utf8_bin NOT NULL,
  `description` text COLLATE utf8_bin NOT NULL,
  `version` varchar(255) COLLATE utf8_bin NOT NULL,
  `icon` VARCHAR(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  `namespace` varchar(255) COLLATE utf8_unicode_ci NOT NULL DEFAULT "misp",
  PRIMARY KEY (id),
  INDEX `name` (`name`),
  INDEX `uuid` (`uuid`),
  INDEX `type` (`type`),
  INDEX `namespace` (`namespace`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- -------------------------------------------------------

--
-- Table structure for `galaxy_clusters`
--


CREATE TABLE IF NOT EXISTS galaxy_clusters (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) COLLATE utf8_bin NOT NULL,
  `type` varchar(255) COLLATE utf8_bin NOT NULL,
  `value` text COLLATE utf8_bin NOT NULL,
  `tag_name` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  `description` text COLLATE utf8_bin NOT NULL,
  `galaxy_id` int(11) NOT NULL,
  `source` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  `authors` text COLLATE utf8_bin NOT NULL,
  `version` int(11) DEFAULT 0,
  PRIMARY KEY (id),
  INDEX `value` (`value`(255)),
  INDEX `uuid` (`uuid`),
  INDEX `galaxy_id` (`galaxy_id`),
  INDEX `version` (`version`),
  INDEX `tag_name` (`tag_name`),
  INDEX `type` (`type`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- -------------------------------------------------------

--
-- Table structure for `galaxy_elements`
--

CREATE TABLE IF NOT EXISTS galaxy_elements (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `galaxy_cluster_id` int(11) NOT NULL,
  `key` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  `value` text COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `key` (`key`),
  INDEX `value` (`value`(255)),
  INDEX `galaxy_cluster_id` (`galaxy_cluster_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- -------------------------------------------------------

--
-- Table structure for `galaxy_reference`
--

CREATE TABLE IF NOT EXISTS galaxy_reference (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `galaxy_cluster_id` int(11) NOT NULL,
  `referenced_galaxy_cluster_id` int(11) NOT NULL,
  `referenced_galaxy_cluster_uuid` varchar(255) COLLATE utf8_bin NOT NULL,
  `referenced_galaxy_cluster_type` text COLLATE utf8_bin NOT NULL,
  `referenced_galaxy_cluster_value` text COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (id),
  INDEX `galaxy_cluster_id` (`galaxy_cluster_id`),
  INDEX `referenced_galaxy_cluster_id` (`referenced_galaxy_cluster_id`),
  INDEX `referenced_galaxy_cluster_value` (`referenced_galaxy_cluster_value`(255)),
  INDEX `referenced_galaxy_cluster_type` (`referenced_galaxy_cluster_type`(255))

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `jobs`
--

CREATE TABLE IF NOT EXISTS `jobs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `worker` varchar(32) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `job_type` varchar(32) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `job_input` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `status` tinyint(4) NOT NULL DEFAULT 0,
  `retries` int(11) NOT NULL DEFAULT 0,
  `message` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `progress` int(11) NOT NULL DEFAULT 0,
  `org_id` int(11) NOT NULL DEFAULT 0,
  `process_id` varchar(32) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `logs`
--

CREATE TABLE IF NOT EXISTS `logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` text CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  `created` datetime NOT NULL,
  `model` varchar(80) COLLATE utf8_bin NOT NULL,
  `model_id` int(11) NOT NULL,
  `action` varchar(20) COLLATE utf8_bin NOT NULL,
  `user_id` int(11) NOT NULL,
  `change` text COLLATE utf8_bin,
  `email` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT "",
  `org` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT "",
  `description` text CHARACTER SET utf8 COLLATE utf8_bin,
  `ip` varchar(45) COLLATE utf8_bin NOT NULL DEFAULT "",
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `news`
--

CREATE TABLE IF NOT EXISTS `news` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message` text COLLATE utf8_bin NOT NULL,
  `title` text COLLATE utf8_bin NOT NULL,
  `user_id` int(11) NOT NULL,
  `date_created` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- -------------------------------------------------------

--
-- Table structure for `noticelists`
--

CREATE TABLE IF NOT EXISTS `noticelists` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
    `expanded_name` text COLLATE utf8_unicode_ci NOT NULL,
    `ref` text COLLATE utf8_unicode_ci,
    `geographical_area` varchar(255) COLLATE utf8_unicode_ci,
    `version` int(11) NOT NULL DEFAULT 1,
    `enabled` tinyint(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`),
    INDEX `name` (`name`),
    INDEX `geographical_area` (`geographical_area`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- -------------------------------------------------------

--
-- Table structure for `noticelist_entries`
--

CREATE TABLE IF NOT EXISTS `noticelist_entries` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `noticelist_id` int(11) NOT NULL,
    `data` text COLLATE utf8_unicode_ci NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `noticelist_id` (`noticelist_id`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- -------------------------------------------------------

--
-- Table structure for `org_blacklists`
--

CREATE TABLE IF NOT EXISTS `org_blacklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `created` datetime NOT NULL,
  PRIMARY KEY (`id`),
  `org_name` varchar(255) COLLATE utf8_bin NOT NULL,
  `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `objects`
--

CREATE TABLE IF NOT EXISTS objects (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `meta-category` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `description` text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `template_uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
  `template_version` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11),
  `comment` text COLLATE utf8_bin NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  INDEX `name` (`name`),
  INDEX `template_uuid` (`template_uuid`),
  INDEX `template_version` (`template_version`),
  INDEX `meta-category` (`meta-category`),
  INDEX `event_id` (`event_id`),
  INDEX `uuid` (`uuid`),
  INDEX `timestamp` (`timestamp`),
  INDEX `distribution` (`distribution`),
  INDEX `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `object_object_references`
--

CREATE TABLE IF NOT EXISTS object_references (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `object_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `source_uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
  `referenced_uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
  `referenced_id` int(11) NOT NULL,
  `referenced_type` int(11) NOT NULL DEFAULT 0,
  `relationship_type` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `comment` text COLLATE utf8_bin NOT NULL,
  `deleted` TINYINT NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  INDEX `source_uuid` (`source_uuid`),
  INDEX `referenced_uuid` (`referenced_uuid`),
  INDEX `timestamp` (`timestamp`),
  INDEX `object_id` (`object_id`),
  INDEX `referenced_id` (`referenced_id`),
  INDEX `relationship_type` (`relationship_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `object_relationships`
--

CREATE TABLE IF NOT EXISTS object_relationships (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `version` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `description` text COLLATE utf8_bin NOT NULL,
  `format` text COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (id),
  INDEX `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `object_templates`
--

CREATE TABLE IF NOT EXISTS object_templates (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `meta-category` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `description` text COLLATE utf8_bin,
  `version` int(11) NOT NULL,
  `requirements` text COLLATE utf8_bin,
  `fixed` tinyint(1) NOT NULL DEFAULT 0,
  `active` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  INDEX `user_id` (`user_id`),
  INDEX `org_id` (`org_id`),
  INDEX `uuid` (`uuid`),
  INDEX `name` (`name`),
  INDEX `meta-category` (`meta-category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `object_template_elements`
--

CREATE TABLE IF NOT EXISTS object_template_elements (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `object_template_id` int(11) NOT NULL,
  `object_relation` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin,
  `type` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin,
  `ui-priority` int(11) NOT NULL,
  `categories` text COLLATE utf8_bin,
  `sane_default` text COLLATE utf8_bin,
  `values_list` text COLLATE utf8_bin,
  `description` text COLLATE utf8_bin,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  `multiple` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  INDEX `object_relation` (`object_relation`),
  INDEX `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `organisations`
--

CREATE TABLE `organisations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8_bin NOT NULL,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `type` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `nationality` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `sector` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `created_by` int(11) NOT NULL DEFAULT 0,
  `uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
  `contacts` text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `local` tinyint(1) NOT NULL DEFAULT 0,
  `restricted_to_domain` text COLLATE utf8_bin,
  `landingpage` text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  PRIMARY KEY (`id`),
  INDEX `uuid` (`uuid`),
  INDEX `name` (`name`(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS `org_blacklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `created` datetime NOT NULL,
  `org_name` varchar(255) COLLATE utf8_bin NOT NULL,
  `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  PRIMARY KEY (`id`),
  INDEX `org_uuid` (`org_uuid`),
  INDEX `org_name` (`org_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
-- --------------------------------------------------------

--
-- Table structure for table `posts`
--

CREATE TABLE IF NOT EXISTS `posts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `user_id` int(11) NOT NULL,
  `contents` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `post_id` int(11) NOT NULL DEFAULT 0,
  `thread_id` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `post_id` (`post_id`),
  INDEX `thread_id` (`thread_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `regexp`
--

CREATE TABLE IF NOT EXISTS `regexp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `regexp` varchar(255) COLLATE utf8_bin NOT NULL,
  `replacement` varchar(255) COLLATE utf8_bin NOT NULL,
  `type` varchar(100) COLLATE utf8_bin NOT NULL DEFAULT 'ALL',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `roles`
--

CREATE TABLE IF NOT EXISTS `roles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8_bin NOT NULL,
  `created` datetime DEFAULT NULL,
  `modified` datetime DEFAULT NULL,
  `perm_add` tinyint(1) DEFAULT NULL,
  `perm_modify` tinyint(1) DEFAULT NULL,
  `perm_modify_org` tinyint(1) DEFAULT NULL,
  `perm_publish` tinyint(1) DEFAULT NULL,
  `perm_delegate` tinyint(1) NOT NULL DEFAULT 0,
  `perm_sync` tinyint(1) DEFAULT NULL,
  `perm_admin` tinyint(1) DEFAULT NULL,
  `perm_audit` tinyint(1) DEFAULT NULL,
  `perm_full` tinyint(1) DEFAULT NULL,
  `perm_auth` tinyint(1) NOT NULL DEFAULT 0,
  `perm_site_admin` tinyint(1) NOT NULL DEFAULT 0,
  `perm_regexp_access` tinyint(1) NOT NULL DEFAULT 0,
  `perm_tagger` tinyint(1) NOT NULL DEFAULT 0,
  `perm_template` tinyint(1) NOT NULL DEFAULT 0,
  `perm_sharing_group` tinyint(1) NOT NULL DEFAULT 0,
  `perm_tag_editor` tinyint(1) NOT NULL DEFAULT 0,
  `perm_sighting` tinyint(1) NOT NULL DEFAULT 0,
  `perm_object_template` tinyint(1) NOT NULL DEFAULT 0,
  `default_role` tinyint(1) NOT NULL DEFAULT 0,
  `memory_limit` VARCHAR(255) COLLATE utf8_bin DEFAULT "",
  `max_execution_time` VARCHAR(255) COLLATE utf8_bin DEFAULT "",
  `restricted_to_site_admin` tinyint(1) NOT NULL DEFAULT 0,
  `perm_publish_zmq` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `servers`
--

CREATE TABLE IF NOT EXISTS `servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8_bin NOT NULL,
  `url` varchar(255) COLLATE utf8_bin NOT NULL,
  `authkey` varchar(40) COLLATE utf8_bin NOT NULL,
  `org_id` int(11) NOT NULL,
  `push` tinyint(1) NOT NULL,
  `pull` tinyint(1) NOT NULL,
  `lastpulledid` int(11) DEFAULT NULL,
  `lastpushedid` int(11) DEFAULT NULL,
  `organization` varchar(10) COLLATE utf8_bin DEFAULT NULL,
  `remote_org_id` int(11) NOT NULL,
  `publish_without_email` tinyint(1) NOT NULL DEFAULT 0,
  `unpublish_event` tinyint(1) NOT NULL DEFAULT 0,
  `self_signed` tinyint(1) NOT NULL,
  `pull_rules` text COLLATE utf8_bin NOT NULL,
  `push_rules` text COLLATE utf8_bin NOT NULL,
  `cert_file` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  `client_cert_file` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  `internal` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `org_id` (`org_id`),
  INDEX `remote_org_id` (`remote_org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table ``)ributes`
--

CREATE TABLE IF NOT EXISTS `shadow_attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `old_id` int(11) DEFAULT 0,
  `event_id` int(11) NOT NULL,
  `type` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `category` varchar(255) COLLATE utf8_bin NOT NULL,
  `value1` text COLLATE utf8_bin,
  `to_ids` tinyint(1) NOT NULL DEFAULT 1,
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `value2` text COLLATE utf8_bin,
  `org_id` int(11) NOT NULL,
  `email` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `event_org_id` int(11) NOT NULL,
  `comment` text COLLATE utf8_bin NOT NULL,
  `event_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `proposal_to_delete` BOOLEAN NOT NULL DEFAULT 0,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `event_id` (`event_id`),
  INDEX `event_uuid` (`event_uuid`),
  INDEX `event_org_id` (`event_org_id`),
  INDEX `uuid` (`uuid`),
  INDEX `old_id` (`old_id`),
  INDEX `value1` (`value1`(255)),
  INDEX `value2` (`value2`(255)),
  INDEX `type` (`type`),
  INDEX `category` (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `shadow_attribute_correlations`
--

CREATE TABLE IF NOT EXISTS `shadow_attribute_correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `value` text NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `a_distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(11),
  `a_sharing_group_id` int(11),
  `attribute_id` int(11) NOT NULL,
  `1_shadow_attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `1_event_id` int(11) NOT NULL,
  `info` text COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `org_id` (`org_id`),
  INDEX `attribute_id` (`attribute_id`),
  INDEX `a_sharing_group_id` (`a_sharing_group_id`),
  INDEX `event_id` (`event_id`),
  INDEX `1_event_id` (`1_event_id`),
  INDEX `sharing_group_id` (`sharing_group_id`),
  INDEX `1_shadow_attribute_id` (`1_shadow_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `sharing_group_orgs`
--

CREATE TABLE `sharing_group_orgs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sharing_group_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `extend` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `org_id` (`org_id`),
  INDEX `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `sharing_group_servers`
--

CREATE TABLE `sharing_group_servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sharing_group_id` int(11) NOT NULL,
  `server_id` int(11) NOT NULL,
  `all_orgs` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `server_id` (`server_id`),
  INDEX `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `sharing_groups`
--

CREATE TABLE `sharing_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `releasability` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `organisation_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  `org_id` int(11) NOT NULL,
  `sync_user_id` int(11) NOT NULL DEFAULT 0,
  `active` tinyint(1) NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `local` tinyint(1) NOT NULL,
  `roaming` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `org_id` (`org_id`),
  INDEX `sync_user_id` (`sync_user_id`),
  UNIQUE INDEX `uuid` (`uuid`),
  INDEX `organisation_uuid` (`organisation_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table sightings
--

CREATE TABLE IF NOT EXISTS sightings (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `date_sighting` bigint(20) NOT NULL,
  `uuid` varchar(255) COLLATE utf8_bin DEFAULT "",
  `source` varchar(255) COLLATE utf8_bin DEFAULT "",
  `type` int(11) DEFAULT 0,
  PRIMARY KEY (id),
  INDEX `attribute_id` (`attribute_id`),
  INDEX `event_id` (`event_id`),
  INDEX `org_id` (`org_id`),
  INDEX `uuid` (`uuid`),
  INDEX `source` (`source`),
  INDEX `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `tags`
--

CREATE TABLE IF NOT EXISTS `tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `colour` varchar(7) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `exportable` tinyint(1) NOT NULL,
  `org_id` tinyint(1) NOT NULL DEFAULT 0,
  `user_id` int(11) NOT NULL DEFAULT 0,
  `hide_tag` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `name` (`name`(255)),
  INDEX `org_id` (`org_id`),
  INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


-- --------------------------------------------------------

--
-- Table structure for table `tasks`
--

CREATE TABLE IF NOT EXISTS `tasks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `timer` int(11) NOT NULL,
  `scheduled_time` varchar(8) NOT NULL DEFAULT '6:00',
  `process_id` varchar(32) DEFAULT NULL,
  `description` varchar(255) NOT NULL,
  `next_execution_time` int(11) NOT NULL,
  `message` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `taxonomies`
--

CREATE TABLE IF NOT EXISTS `taxonomies` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `namespace` varchar(255) COLLATE utf8_bin NOT NULL,
  `description` text COLLATE utf8_bin NOT NULL,
  `version` int(11) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `taxonomy_entries`
--

CREATE TABLE IF NOT EXISTS `taxonomy_entries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `taxonomy_predicate_id` int(11) NOT NULL,
  `value` text COLLATE utf8_bin NOT NULL,
  `expanded` text COLLATE utf8_bin,
  `colour` varchar(7) CHARACTER SET utf8 COLLATE utf8_bin,
  PRIMARY KEY (`id`),
  INDEX `taxonomy_predicate_id` (`taxonomy_predicate_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `taxonomy_predicates`
--

CREATE TABLE IF NOT EXISTS `taxonomy_predicates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `taxonomy_id` int(11) NOT NULL,
  `value` text COLLATE utf8_bin NOT NULL,
  `expanded` text COLLATE utf8_bin,
  `colour` varchar(7) CHARACTER SET utf8 COLLATE utf8_bin,
  PRIMARY KEY (`id`),
  INDEX `taxonomy_id` (`taxonomy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `templates`
--

CREATE TABLE IF NOT EXISTS `templates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `description` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `org` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `share` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_elements`
--

CREATE TABLE IF NOT EXISTS `template_elements` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_id` int(11) NOT NULL,
  `position` int(11) NOT NULL,
  `element_definition` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_element_attributes`
--

CREATE TABLE IF NOT EXISTS `template_element_attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_element_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT 1,
  `category` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `complex` tinyint(1) NOT NULL,
  `type` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `mandatory` tinyint(1) NOT NULL,
  `batch` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_element_files`
--

CREATE TABLE IF NOT EXISTS `template_element_files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_element_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `category` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `malware` tinyint(1) NOT NULL,
  `mandatory` tinyint(1) NOT NULL,
  `batch` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_element_texts`
--

CREATE TABLE IF NOT EXISTS `template_element_texts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `template_element_id` int(11) NOT NULL,
  `text` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `template_tags`
--

CREATE TABLE IF NOT EXISTS `template_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `threads`
--

CREATE TABLE IF NOT EXISTS `threads` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `user_id` int(11) NOT NULL,
  `post_count` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `title` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `org_id` int(11) NOT NULL,
  `sharing_group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `user_id` (`user_id`),
  INDEX `event_id` (`event_id`),
  INDEX `org_id` (`org_id`),
  INDEX `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `threat_levels`
--

CREATE TABLE IF NOT EXISTS `threat_levels` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `form_description` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(255) COLLATE utf8_bin NOT NULL,
  `org_id` int(11) NOT NULL,
  `server_id` int(11) NOT NULL DEFAULT 0,
  `email` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `autoalert` tinyint(1) NOT NULL DEFAULT 0,
  `authkey` varchar(40) COLLATE utf8_bin DEFAULT NULL,
  `invited_by` int(11) NOT NULL DEFAULT 0,
  `gpgkey` longtext COLLATE utf8_bin,
  `certif_public` longtext COLLATE utf8_bin,
  `nids_sid` int(15) NOT NULL DEFAULT 0,
  `termsaccepted` tinyint(1) NOT NULL DEFAULT 0,
  `newsread` int(11) unsigned DEFAULT 0,
  `role_id` int(11) NOT NULL DEFAULT 0,
  `change_pw` tinyint(4) NOT NULL DEFAULT 0,
  `contactalert` tinyint(1) NOT NULL DEFAULT 0,
  `disabled` BOOLEAN NOT NULL DEFAULT 0,
  `expiration` datetime DEFAULT NULL,
  `current_login` int(11) DEFAULT 0,
  `last_login` int(11) DEFAULT 0,
  `force_logout` tinyint(1) NOT NULL DEFAULT 0,
  `date_created` bigint(20),
  `date_modified` bigint(20),
  PRIMARY KEY (`id`),
  INDEX `email` (`email`),
  INDEX `org_id` (`org_id`),
  INDEX `server_id` (`server_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `warninglists`
--

CREATE TABLE IF NOT EXISTS `warninglists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8_bin NOT NULL,
  `type` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT 'string',
  `description` text COLLATE utf8_bin NOT NULL,
  `version` int(11) NOT NULL DEFAULT '1',
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `warninglist_entry_count` int(11) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `warninglist_entries`
--

CREATE TABLE IF NOT EXISTS `warninglist_entries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `warninglist_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `warninglist_id` (`warninglist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `warninglist_types`
--

CREATE TABLE IF NOT EXISTS `warninglist_types` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(255) COLLATE utf8_bin NOT NULL,
  `warninglist_id` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `whitelist`
--

CREATE TABLE IF NOT EXISTS `whitelist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Default values for initial installation
--

INSERT INTO `admin_settings` (`id`, `setting`, `value`) VALUES
(1, 'db_version', '11');

INSERT INTO `feeds` (`id`, `provider`, `name`, `url`, `distribution`, `default`, `enabled`) VALUES
(1, 'CIRCL', 'CIRCL OSINT Feed', 'https://www.circl.lu/doc/misp/feed-osint', 3, 1, 0),
(2, 'Botvrij.eu', 'The Botvrij.eu Data', 'http://www.botvrij.eu/data/feed-osint', 3, 1, 0);

 INSERT INTO `regexp` (`id`, `regexp`, `replacement`, `type`) VALUES
 (1, '/.:.ProgramData./i', '%ALLUSERSPROFILE%\\\\', 'ALL'),
 (2, '/.:.Documents and Settings.All Users./i', '%ALLUSERSPROFILE%\\\\', 'ALL'),
 (3, '/.:.Program Files.Common Files./i', '%COMMONPROGRAMFILES%\\\\', 'ALL'),
 (4, '/.:.Program Files (x86).Common Files./i', '%COMMONPROGRAMFILES(x86)%\\\\', 'ALL'),
 (5, '/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i', '%TEMP%\\\\', 'ALL'),
 (6, '/.:.ProgramData./i', '%PROGRAMDATA%\\\\', 'ALL'),
 (7, '/.:.Program Files./i', '%PROGRAMFILES%\\\\', 'ALL'),
 (8, '/.:.Program Files (x86)./i', '%PROGRAMFILES(X86)%\\\\', 'ALL'),
 (9, '/.:.Users.Public./i', '%PUBLIC%\\\\', 'ALL'),
 (10, '/.:.Documents and Settings\\\\(.*?)\\\\Local Settings.Temp./i', '%TEMP%\\\\', 'ALL'),
 (11, '/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i', '%TEMP%\\\\', 'ALL'),
 (12, '/.:.Users\\\\(.*?)\\\\AppData.Local./i', '%LOCALAPPDATA%\\\\', 'ALL'),
 (13, '/.:.Users\\\\(.*?)\\\\AppData.Roaming./i', '%APPDATA%\\\\', 'ALL'),
 (14, '/.:.Users\\\\(.*?)\\\\Application Data./i', '%APPDATA%\\\\', 'ALL'),
 (15, '/.:.Windows\\\\(.*?)\\\\Application Data./i', '%APPDATA%\\\\', 'ALL'),
 (16, '/.:.Users\\\\(.*?)\\\\/i', '%USERPROFILE%\\\\', 'ALL'),
 (17, '/.:.DOCUME~1.\\\\(.*?)\\\\/i', '%USERPROFILE%\\\\', 'ALL'),
 (18, '/.:.Documents and Settings\\\\(.*?)\\\\/i', '%USERPROFILE%\\\\', 'ALL'),
 (19, '/.:.Windows./i', '%WINDIR%\\\\', 'ALL'),
 (20, '/.:.Windows./i', '%WINDIR%\\\\', 'ALL'),
 (21, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}/i', 'HKCU', 'ALL'),
 (22, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}/i', 'HKCU', 'ALL'),
 (23, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}/i', 'HKCU', 'ALL'),
 (24, '/.REGISTRY.MACHINE./i', 'HKLM\\\\', 'ALL'),
 (25, '/.Registry.Machine./i', 'HKLM\\\\', 'ALL'),
 (26, '/%USERPROFILE%.Application Data.Microsoft.UProof/i', '', 'ALL'),
 (27, '/%USERPROFILE%.Local Settings.History/i', '', 'ALL'),
 (28, '/%APPDATA%.Microsoft.UProof/i ', '', 'ALL'),
 (29, '/%LOCALAPPDATA%.Microsoft.Windows.Temporary Internet Files/i', '', 'ALL');

-- --------------------------------------------------------

--
-- Creating initial roles
--
-- 1. Admin - has full access
-- 2. Org Admin - read/write/publish/audit/admin/sync/auth/tagger
-- 3. User - User - Read / Write, no other permissions (default)
-- 4. Publisher
-- 5. Sync user - read/write/publish/sync/auth
-- 6. Automation user - read/write/publish/auth
-- 7. Read Only - read
--

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `default_role`)
VALUES (1, 'admin', NOW(), NOW(), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0);

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `default_role`)
VALUES (2, 'Org Admin', NOW(), NOW(), 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0);

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `default_role`)
VALUES (3, 'User', NOW(), NOW(), 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1);

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `default_role`)
VALUES (4, 'Publisher', NOW(), NOW(), 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0);

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `default_role`)
VALUES (5, 'Sync user', NOW(), NOW(), 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0);

INSERT INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `default_role`)
VALUES (6, 'Read Only', NOW(), NOW(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

-- --------------------------------------------------------

--
-- Initial threat levels
--

INSERT INTO `threat_levels` (`id`, `name`, `description`, `form_description`)
VALUES
  (1, 'High', '*high* means sophisticated APT malware or 0-day attack', 'Sophisticated APT malware or 0-day attack'),
  (2, 'Medium', '*medium* means APT malware', 'APT malware'),
  (3, 'Low', '*low* means mass-malware', 'Mass-malware'),
  (4, 'Undefined', '*undefined* no risk', 'No risk');

-- --------------------------------------------------------

--
-- Default templates
--

INSERT INTO `templates` (`id`, `name`, `description`, `org`, `share`) VALUES
(1, 'Phishing E-mail', 'Create a MISP event about a Phishing E-mail.', 'MISP', 1),
(2, 'Phishing E-mail with malicious attachment', 'A MISP event based on Spear-phishing containing a malicious attachment. This event can include anything from the description of the e-mail itself, the malicious attachment and its description as well as the results of the analysis done on the malicious f', 'MISP', 1),
(3, 'Malware Report', 'This is a template for a generic malware report. ', 'MISP', 1),
(4, 'Indicator List', 'A simple template for indicator lists.', 'MISP', 1);

INSERT INTO `template_elements` (`id`, `template_id`, `position`, `element_definition`) VALUES
(1, 1, 2, 'attribute'),
(2, 1, 3, 'attribute'),
(3, 1, 1, 'text'),
(4, 1, 4, 'attribute'),
(5, 1, 5, 'text'),
(6, 1, 6, 'attribute'),
(7, 1, 7, 'attribute'),
(8, 1, 8, 'attribute'),
(11, 2, 1, 'text'),
(12, 2, 2, 'attribute'),
(13, 2, 3, 'text'),
(14, 2, 4, 'file'),
(15, 2, 5, 'attribute'),
(16, 2, 10, 'text'),
(17, 2, 6, 'attribute'),
(18, 2, 7, 'attribute'),
(19, 2, 8, 'attribute'),
(20, 2, 9, 'attribute'),
(21, 2, 11, 'file'),
(22, 2, 12, 'attribute'),
(23, 2, 13, 'attribute'),
(24, 2, 14, 'attribute'),
(25, 2, 15, 'attribute'),
(26, 2, 16, 'attribute'),
(27, 2, 17, 'attribute'),
(28, 2, 18, 'attribute'),
(29, 3, 1, 'text'),
(30, 3, 2, 'file'),
(31, 3, 4, 'text'),
(32, 3, 9, 'text'),
(33, 3, 11, 'text'),
(34, 3, 10, 'attribute'),
(35, 3, 12, 'attribute'),
(36, 3, 3, 'attribute'),
(37, 3, 5, 'attribute'),
(38, 3, 6, 'attribute'),
(39, 3, 7, 'attribute'),
(40, 3, 8, 'file'),
(41, 3, 13, 'text'),
(42, 3, 14, 'attribute'),
(43, 3, 15, 'attribute'),
(44, 3, 16, 'attribute'),
(45, 4, 1, 'text'),
(46, 4, 2, 'attribute'),
(47, 4, 3, 'attribute');

INSERT INTO `template_element_attributes` (`id`, `template_element_id`, `name`, `description`, `to_ids`, `category`, `complex`, `type`, `mandatory`, `batch`) VALUES
(1, 1, 'From address', 'The source address from which the e-mail was sent.', 1, 'Payload delivery', 0, 'email-src', 1, 1),
(2, 2, 'Malicious url', 'The malicious url in the e-mail body.', 1, 'Payload delivery', 0, 'url', 1, 1),
(3, 4, 'E-mail subject', 'The subject line of the e-mail.', 0, 'Payload delivery', 0, 'email-subject', 1, 0),
(4, 6, 'Spoofed source address', 'If an e-mail address was spoofed, specify which.', 1, 'Payload delivery', 0, 'email-src', 0, 0),
(5, 7, 'Source IP', 'The source IP from which the e-mail was sent', 1, 'Payload delivery', 0, 'ip-src', 0, 1),
(6, 8, 'X-mailer header', 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 1, 'Payload delivery', 0, 'text', 0, 1),
(7, 12, 'From address', 'The source address from which the e-mail was sent', 1, 'Payload delivery', 0, 'email-src', 1, 1),
(8, 15, 'Spoofed From Address', 'The spoofed source address from which the e-mail appears to be sent.', 1, 'Payload delivery', 0, 'email-src', 0, 1),
(9, 17, 'E-mail Source IP', 'The IP address from which the e-mail was sent.', 1, 'Payload delivery', 0, 'ip-src', 0, 1),
(10, 18, 'X-mailer header', 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 1, 'Payload delivery', 0, 'text', 0, 0),
(11, 19, 'Malicious URL in the e-mail', 'If there was a malicious URL (or several), please specify it here', 1, 'Payload delivery', 0, 'ip-dst', 0, 1),
(12, 20, 'Exploited vulnerablity', 'The vulnerabilities exploited during the payload delivery.', 0, 'Payload delivery', 0, 'vulnerability', 0, 1),
(13, 22, 'C2 information', 'Command and Control information detected during the analysis.', 1, 'Network activity', 1, 'CnC', 0, 1),
(14, 23, 'Artifacts dropped (File)', 'Any information about the files dropped during the analysis', 1, 'Artifacts dropped', 1, 'File', 0, 1),
(15, 24, 'Artifacts dropped (Registry key)', 'Any registry keys touched during the analysis', 1, 'Artifacts dropped', 0, 'regkey', 0, 1),
(16, 25, 'Artifacts dropped (Registry key + value)', 'Any registry keys created or altered together with the value.', 1, 'Artifacts dropped', 0, 'regkey|value', 0, 1),
(17, 26, 'Persistance mechanism (filename)', 'Filenames (or filenames with filepaths) used as a persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey|value', 0, 1),
(18, 27, 'Persistence mechanism (Registry key)', 'Any registry keys touched as part of the persistence mechanism during the analysis ', 1, 'Persistence mechanism', 0, 'regkey', 0, 1),
(19, 28, 'Persistence mechanism (Registry key + value)', 'Any registry keys created or modified together with their values used by the persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey|value', 0, 1),
(20, 34, 'C2 Information', 'You can drop any urls, domains, hostnames or IP addresses that were detected as the Command and Control during the analysis here. ', 1, 'Network activity', 1, 'CnC', 0, 1),
(21, 35, 'Other Network Activity', 'Drop any applicable information about other network activity here. The attributes created here will NOT be marked for IDS exports.', 0, 'Network activity', 1, 'CnC', 0, 1),
(22, 36, 'Vulnerability', 'The vulnerability or vulnerabilities that the sample exploits', 0, 'Payload delivery', 0, 'vulnerability', 0, 1),
(23, 37, 'Artifacts Dropped (File)', 'Insert any data you have on dropped files here.', 1, 'Artifacts dropped', 1, 'File', 0, 1),
(24, 38, 'Artifacts dropped (Registry key)', 'Any registry keys touched during the analysis', 1, 'Artifacts dropped', 0, 'regkey', 0, 1),
(25, 39, 'Artifacts dropped (Registry key + value)', 'Any registry keys created or altered together with the value.', 1, 'Artifacts dropped', 0, 'regkey|value', 0, 1),
(26, 42, 'Persistence mechanism (filename)', 'Insert any filenames used by the persistence mechanism.', 1, 'Persistence mechanism', 0, 'filename', 0, 1),
(27, 43, 'Persistence Mechanism (Registry key)', 'Paste any registry keys that were created or modified as part of the persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey', 0, 1),
(28, 44, 'Persistence Mechanism (Registry key and value)', 'Paste any registry keys together with the values contained within created or modified by the persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey|value', 0, 1),
(29, 46, 'Network Indicators', 'Paste any combination of IP addresses, hostnames, domains or URL', 1, 'Network activity', 1, 'CnC', 0, 1),
(30, 47, 'File Indicators', 'Paste any file hashes that you have (MD5, SHA1, SHA256) or filenames below. You can also add filename and hash pairs by using the following syntax for each applicable column: filename|hash ', 1, 'Payload installation', 1, 'File', 0, 1);

INSERT INTO `template_element_files` (`id`, `template_element_id`, `name`, `description`, `category`, `malware`, `mandatory`, `batch`) VALUES
(1, 14, 'Malicious Attachment', 'The file (or files) that was (were) attached to the e-mail itself.', 'Payload delivery', 1, 0, 1),
(2, 21, 'Payload installation', 'Payload installation detected during the analysis', 'Payload installation', 1, 0, 1),
(3, 30, 'Malware sample', 'The sample that the report is based on', 'Payload delivery', 1, 0, 0),
(4, 40, 'Artifacts dropped (Sample)', 'Upload any files that were dropped during the analysis.', 'Artifacts dropped', 1, 0, 1);

INSERT INTO `template_element_texts` (`id`, `name`, `template_element_id`, `text`) VALUES
(1, 'Required fields', 3, 'The fields below are mandatory.'),
(2, 'Optional information', 5, 'All of the fields below are optional, please fill out anything that''s applicable.'),
(4, 'Required Fields', 11, 'The following fields are mandatory'),
(5, 'Optional information about the payload delivery', 13, 'All of the fields below are optional, please fill out anything that''s applicable. This section describes the payload delivery, including the e-mail itself, the attached file, the vulnerability it is exploiting and any malicious urls in the e-mail.'),
(6, 'Optional information obtained from analysing the malicious file', 16, 'Information about the analysis of the malware (if applicable). This can include C2 information, artifacts dropped during the analysis, persistance mechanism, etc.'),
(7, 'Malware Sample', 29, 'If you can, please upload the sample that the report revolves around.'),
(8, 'Dropped Artifacts', 31, 'Describe any dropped artifacts that you have encountered during your analysis'),
(9, 'C2 Information', 32, 'The following field deals with Command and Control information obtained during the analysis. All fields are optional.'),
(10, 'Other Network Activity', 33, 'If any other Network activity (such as an internet connection test) was detected during the analysis, please specify it using the following fields'),
(11, 'Persistence mechanism', 41, 'The following fields allow you to describe the persistence mechanism used by the malware'),
(12, 'Indicators', 45, 'Just paste your list of indicators based on type into the appropriate field. All of the fields are optional, so inputting a list of IP addresses into the Network indicator field for example is sufficient to complete this template.');

INSERT INTO `org_blacklists` (`org_uuid`, `created`, `org_name`, `comment`) VALUES
('58d38339-7b24-4386-b4b4-4c0f950d210f', NOW(), 'Setec Astrononomy', 'default example'),
('58d38326-eda8-443a-9fa8-4e12950d210f', NOW(), 'Acme Finance', 'default example');
