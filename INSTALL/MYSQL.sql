-- MISP MySQL install baseline, equivalent to db_version 159.
--
-- Generated with `Console/cake Admin dumpInstallBaseline` from a reference
-- database; regenerate it the same way rather than editing the DDL by
-- hand. The seed block after the DDL is what a fresh instance starts
-- with; the upgrade system carries it the rest of the way.

/*!40101 SET NAMES utf8mb4 */;
ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;

CREATE TABLE `access_logs` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `created` datetime(4) NOT NULL,
    `user_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    `authkey_id` bigint DEFAULT NULL,
    `ip` varbinary(16) DEFAULT NULL,
    `request_method` tinyint NOT NULL,
    `user_agent` varchar(255) DEFAULT NULL,
    `request_id` varchar(255) DEFAULT NULL,
    `controller` varchar(20) NOT NULL,
    `action` varchar(191) NOT NULL,
    `url` varchar(255) NOT NULL,
    `request` blob DEFAULT NULL,
    `response_code` smallint NOT NULL,
    `memory_usage` int NOT NULL,
    `duration` int NOT NULL,
    `query_count` int NOT NULL,
    `query_log` blob DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `admin_settings` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `setting` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `value` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `setting` (`setting`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `analyst_data_blocklists` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `analyst_data_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` datetime NOT NULL,
    `analyst_data_info` text NOT NULL,
    `comment` text DEFAULT NULL,
    `analyst_data_orgc` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `analyst_data_orgc` (`analyst_data_orgc`),
    INDEX `analyst_data_uuid` (`analyst_data_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `analyst_graphs` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    `authors` text DEFAULT NULL,
    `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` datetime NOT NULL,
    `modified` datetime NOT NULL,
    `distribution` tinyint NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `locked` tinyint(1) DEFAULT '0' NOT NULL,
    `name` varchar(191) NOT NULL,
    `description` text DEFAULT NULL,
    `content` longtext NOT NULL,
    `content_size` int DEFAULT 0 NOT NULL,
    `node_count` int DEFAULT 0 NOT NULL,
    `revision` int DEFAULT 1 NOT NULL,
    `forked_from_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `distribution` (`distribution`),
    INDEX `forked_from_uuid` (`forked_from_uuid`),
    INDEX `object_type` (`object_type`),
    INDEX `object_uuid` (`object_uuid`),
    INDEX `org_uuid` (`org_uuid`),
    INDEX `orgc_uuid` (`orgc_uuid`),
    INDEX `sharing_group_id` (`sharing_group_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `analyst_profiles` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `name` varchar(191) NOT NULL,
    `description` text DEFAULT NULL,
    `user_id` bigint DEFAULT NULL,
    `org_id` bigint DEFAULT NULL,
    `default` tinyint(1) DEFAULT '0' NOT NULL,
    `shared` tinyint(1) DEFAULT '0' NOT NULL,
    `enabled` tinyint(1) DEFAULT '1' NOT NULL,
    `version` int DEFAULT 1 NOT NULL,
    `revision` int DEFAULT 1 NOT NULL,
    `shipped_revision` int DEFAULT NULL,
    `parameters` longtext DEFAULT NULL,
    `created` datetime NOT NULL,
    `modified` datetime NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `default` (`default`),
    INDEX `enabled` (`enabled`),
    INDEX `name` (`name`),
    INDEX `org_id` (`org_id`),
    INDEX `shared` (`shared`),
    INDEX `user_id` (`user_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `analyst_profile_selections` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `org_id` bigint NOT NULL,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `modified` datetime NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `org_id` (`org_id`),
    INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `attachment_scans` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `type` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `attribute_id` bigint NOT NULL,
    `infected` tinyint(1) NOT NULL,
    `malware_name` varchar(191) DEFAULT NULL,
    `timestamp` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `index` (`type`, `attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `attributes` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `event_id` bigint NOT NULL,
    `object_id` bigint DEFAULT 0 NOT NULL,
    `object_relation` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `category` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `type` varchar(100) NOT NULL,
    `value1_id` bigint DEFAULT NULL,
    `value2_id` bigint DEFAULT NULL,
    `to_ids` tinyint(1) DEFAULT '1' NOT NULL,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `created` bigint DEFAULT 0 NOT NULL,
    `distribution` tinyint DEFAULT 0 NOT NULL,
    `sharing_group_id` bigint NOT NULL,
    `comment` text DEFAULT NULL,
    `deleted` tinyint(1) DEFAULT '0' NOT NULL,
    `disable_correlation` tinyint(1) DEFAULT '0' NOT NULL,
    `first_seen` bigint DEFAULT NULL,
    `last_seen` bigint DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `category` (`category`),
    INDEX `created` (`created`),
    INDEX `first_seen` (`first_seen`),
    INDEX `idx_attr_acl_primary` (`deleted`, `distribution`, `sharing_group_id`, `event_id`),
    INDEX `idx_attr_acl_type` (`event_id`, `distribution`, `sharing_group_id`, `deleted`, `type`),
    INDEX `idx_attr_deleted_ts` (`deleted`, `timestamp`, `id`),
    INDEX `idx_attr_obj_dist` (`object_id`, `distribution`),
    INDEX `idx_attr_objrel_acl` (`object_relation`, `event_id`, `distribution`, `sharing_group_id`, `deleted`),
    INDEX `idx_attr_search_core` (`type`, `to_ids`, `deleted`, `distribution`, `sharing_group_id`, `event_id`),
    INDEX `idx_attr_ts_acl` (`timestamp`, `deleted`, `distribution`, `sharing_group_id`, `event_id`),
    INDEX `idx_attr_type_event` (`type`, `event_id`),
    INDEX `idx_attr_type_id` (`type`, `id`),
    INDEX `idx_attr_vid_combo` (`value1_id`, `value2_id`),
    INDEX `idx_event_deleted_object` (`event_id`, `deleted`, `object_id`),
    INDEX `idx_vid1_source` (`event_id`, `value1_id`, `deleted`, `disable_correlation`, `type`, `id`),
    INDEX `idx_vid1_target` (`value1_id`, `event_id`, `deleted`, `disable_correlation`, `type`, `id`),
    INDEX `idx_vid2_source` (`event_id`, `value2_id`, `deleted`, `disable_correlation`, `type`, `id`),
    INDEX `idx_vid2_target` (`value2_id`, `event_id`, `deleted`, `disable_correlation`, `type`, `id`),
    INDEX `last_seen` (`last_seen`),
    INDEX `sharing_group_id` (`sharing_group_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `attribute_tags` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `attribute_id` bigint NOT NULL,
    `event_id` bigint NOT NULL,
    `tag_id` bigint NOT NULL,
    `local` tinyint(1) DEFAULT '0' NOT NULL,
    `relationship_type` varchar(191) DEFAULT '',
    PRIMARY KEY (`id`),
    INDEX `idx_attr_tags_attr_tag` (`attribute_id`, `tag_id`),
    INDEX `idx_attr_tags_event_tag` (`event_id`, `tag_id`),
    INDEX `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

SET SESSION innodb_ft_enable_stopword = 0;
CREATE TABLE `attribute_values` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `value` text NOT NULL,
    `hash` varbinary(32) NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `hash` (`hash`),
    INDEX `value` (`value`(128)),
    FULLTEXT INDEX `value_search` (`value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
SET SESSION innodb_ft_enable_stopword = DEFAULT;

CREATE TABLE `attr_value_counts` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `value_id` bigint NOT NULL,
    `cnt_v1` bigint UNSIGNED DEFAULT 0 NOT NULL,
    `cnt_v2` bigint UNSIGNED DEFAULT 0 NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `value_id` (`value_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `audit_logs` (
    `id` int NOT NULL AUTO_INCREMENT,
    `created` datetime NOT NULL,
    `user_id` int NOT NULL,
    `org_id` int NOT NULL,
    `authkey_id` int DEFAULT NULL,
    `ip` varbinary(16) DEFAULT NULL,
    `request_type` tinyint NOT NULL,
    `request_id` varchar(255) DEFAULT NULL,
    `action` varchar(20) NOT NULL,
    `model` varchar(80) NOT NULL,
    `model_id` int NOT NULL,
    `model_title` text DEFAULT NULL,
    `event_id` int DEFAULT NULL,
    `change` blob DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `event_id` (`event_id`),
    INDEX `model_id` (`model_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `auth_keys` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `authkey` varchar(72) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `authkey_start` varchar(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `authkey_end` varchar(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` bigint NOT NULL,
    `expiration` bigint NOT NULL,
    `read_only` tinyint(1) DEFAULT '0' NOT NULL,
    `user_id` bigint NOT NULL,
    `comment` text DEFAULT NULL,
    `allowed_ips` text DEFAULT NULL,
    `unique_ips` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `authkey_end` (`authkey_end`),
    INDEX `authkey_start` (`authkey_start`),
    INDEX `created` (`created`),
    INDEX `expiration` (`expiration`),
    INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `bookmarks` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `user_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    `name` varchar(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `url` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `exposed_to_org` tinyint(1) DEFAULT '0' NOT NULL,
    `comment` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `name` (`name`),
    INDEX `org_id` (`org_id`),
    INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `bruteforces` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `username` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `expire` datetime NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `cake_sessions` (
    `id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `data` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `expires` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `cerebrates` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(191) NOT NULL,
    `url` varchar(255) NOT NULL,
    `authkey` varbinary(255) NOT NULL,
    `open` tinyint(1) DEFAULT '0',
    `org_id` bigint NOT NULL,
    `pull_orgs` tinyint(1) DEFAULT '0',
    `pull_sharing_groups` tinyint(1) DEFAULT '0',
    `self_signed` tinyint(1) DEFAULT '0',
    `cert_file` varchar(255) DEFAULT NULL,
    `client_cert_file` varchar(255) DEFAULT NULL,
    `internal` tinyint(1) DEFAULT '0' NOT NULL,
    `skip_proxy` tinyint(1) DEFAULT '0' NOT NULL,
    `description` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `org_id` (`org_id`),
    INDEX `url` (`url`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `collections` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `org_id` bigint NOT NULL,
    `orgc_id` bigint NOT NULL,
    `user_id` bigint NOT NULL,
    `created` datetime NOT NULL,
    `modified` datetime NOT NULL,
    `distribution` tinyint NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `name` varchar(191) NOT NULL,
    `type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    `description` mediumtext DEFAULT NULL,
    `locked` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `distribution` (`distribution`),
    INDEX `name` (`name`),
    INDEX `org_id` (`org_id`),
    INDEX `orgc_id` (`orgc_id`),
    INDEX `sharing_group_id` (`sharing_group_id`),
    INDEX `type` (`type`),
    INDEX `user_id` (`user_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `collection_elements` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `element_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `element_sha256` varchar(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `element_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    `collection_id` bigint NOT NULL,
    `description` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `collection_id` (`collection_id`),
    INDEX `element_type` (`element_type`),
    UNIQUE INDEX `unique_element` (`element_uuid`, `collection_id`),
    UNIQUE INDEX `unique_element_sha256` (`element_sha256`, `collection_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `correlation_exclusions` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `value` text NOT NULL,
    `from_json` tinyint(1) DEFAULT '0',
    `comment` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `value` (`value`(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `correlation_rules` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `name` varchar(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `comment` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `selector_type` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `selector_list` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `created` bigint DEFAULT 0 NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `name` (`name`),
    INDEX `selector_type` (`selector_type`),
    INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `cryptographic_keys` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `type` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `parent_id` bigint NOT NULL,
    `parent_type` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `key_data` text DEFAULT NULL,
    `revoked` tinyint(1) DEFAULT '0' NOT NULL,
    `fingerprint` varchar(255) CHARACTER SET ascii COLLATE ascii_bin DEFAULT '' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `fingerprint` (`fingerprint`),
    INDEX `parent_id` (`parent_id`),
    INDEX `parent_type` (`parent_type`),
    INDEX `type` (`type`),
    INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `dashboards` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `name` varchar(191) NOT NULL,
    `description` text DEFAULT NULL,
    `default` tinyint(1) DEFAULT '0' NOT NULL,
    `selectable` tinyint(1) DEFAULT '0' NOT NULL,
    `user_id` bigint DEFAULT 0 NOT NULL,
    `restrict_to_org_id` bigint DEFAULT 0 NOT NULL,
    `restrict_to_role_id` bigint DEFAULT 0 NOT NULL,
    `restrict_to_permission_flag` varchar(191) DEFAULT '' NOT NULL,
    `value` mediumtext DEFAULT NULL,
    `timestamp` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `name` (`name`),
    INDEX `restrict_to_org_id` (`restrict_to_org_id`),
    INDEX `restrict_to_permission_flag` (`restrict_to_permission_flag`),
    INDEX `user_id` (`user_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `decaying_models` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `parameters` text DEFAULT NULL,
    `attribute_types` text DEFAULT NULL,
    `description` text DEFAULT NULL,
    `org_id` bigint DEFAULT NULL,
    `enabled` tinyint(1) DEFAULT '0' NOT NULL,
    `all_orgs` tinyint(1) DEFAULT '1' NOT NULL,
    `ref` text DEFAULT NULL,
    `formula` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `version` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '' NOT NULL,
    `default` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `all_orgs` (`all_orgs`),
    INDEX `enabled` (`enabled`),
    INDEX `name` (`name`),
    INDEX `org_id` (`org_id`),
    INDEX `uuid` (`uuid`),
    INDEX `version` (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `decaying_model_mappings` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `attribute_type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `model_id` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `model_id` (`model_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `default_correlations` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `attribute_id` bigint NOT NULL,
    `object_id` bigint NOT NULL,
    `event_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    `distribution` tinyint NOT NULL,
    `object_distribution` tinyint NOT NULL,
    `event_distribution` tinyint NOT NULL,
    `sharing_group_id` bigint DEFAULT 0 NOT NULL,
    `object_sharing_group_id` bigint DEFAULT 0 NOT NULL,
    `event_sharing_group_id` bigint DEFAULT 0 NOT NULL,
    `1_attribute_id` bigint NOT NULL,
    `1_object_id` bigint NOT NULL,
    `1_event_id` bigint NOT NULL,
    `1_org_id` bigint NOT NULL,
    `1_distribution` tinyint NOT NULL,
    `1_object_distribution` tinyint NOT NULL,
    `1_event_distribution` tinyint NOT NULL,
    `1_sharing_group_id` bigint DEFAULT 0 NOT NULL,
    `1_object_sharing_group_id` bigint DEFAULT 0 NOT NULL,
    `1_event_sharing_group_id` bigint DEFAULT 0 NOT NULL,
    `value_id` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `1_attribute_id` (`1_attribute_id`),
    INDEX `1_event_id` (`1_event_id`),
    INDEX `idx_corr_acl_dst` (`1_object_id`, `1_org_id`, `1_distribution`, `1_sharing_group_id`, `1_event_distribution`, `1_event_sharing_group_id`),
    INDEX `idx_corr_acl_dst_obj` (`1_object_id`, `1_org_id`, `1_distribution`, `1_sharing_group_id`, `1_object_distribution`, `1_object_sharing_group_id`, `1_event_distribution`, `1_event_sharing_group_id`),
    INDEX `idx_corr_acl_src` (`object_id`, `org_id`, `distribution`, `sharing_group_id`, `event_distribution`, `event_sharing_group_id`),
    INDEX `idx_corr_acl_src_obj` (`object_id`, `org_id`, `distribution`, `sharing_group_id`, `object_distribution`, `object_sharing_group_id`, `event_distribution`, `event_sharing_group_id`),
    INDEX `idx_corr_evt_1evt` (`event_id`, `1_event_id`),
    UNIQUE INDEX `unique_correlation` (`attribute_id`, `1_attribute_id`, `value_id`),
    INDEX `value_id` (`value_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `events` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `org_id` bigint NOT NULL,
    `date` date NOT NULL,
    `info` text NOT NULL,
    `user_id` bigint NOT NULL,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `published` tinyint(1) DEFAULT '0' NOT NULL,
    `analysis` tinyint NOT NULL,
    `attribute_count` int UNSIGNED DEFAULT 0,
    `orgc_id` bigint NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `distribution` tinyint DEFAULT 0 NOT NULL,
    `sharing_group_id` bigint NOT NULL,
    `proposal_email_lock` tinyint(1) DEFAULT '0' NOT NULL,
    `locked` tinyint(1) DEFAULT '0' NOT NULL,
    `threat_level_id` bigint NOT NULL,
    `publish_timestamp` bigint DEFAULT 0 NOT NULL,
    `sighting_timestamp` bigint DEFAULT 0 NOT NULL,
    `disable_correlation` tinyint(1) DEFAULT '0' NOT NULL,
    `extends_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT '',
    `protected` tinyint(1) DEFAULT NULL,
    `first_publication` bigint DEFAULT 0 NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `extends_uuid` (`extends_uuid`),
    INDEX `first_publication` (`first_publication`),
    INDEX `idx_evt_acl` (`distribution`, `sharing_group_id`),
    INDEX `idx_evt_acl_flex` (`org_id`, `distribution`, `sharing_group_id`, `id`),
    INDEX `idx_evt_id_acl` (`id`, `org_id`, `distribution`, `sharing_group_id`),
    INDEX `idx_evt_ts_pub` (`timestamp`, `published`),
    INDEX `info` (`info`(255)),
    INDEX `orgc_id` (`orgc_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_blocklists` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `event_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` datetime NOT NULL,
    `event_info` text NOT NULL,
    `comment` text DEFAULT NULL,
    `event_orgc` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `event_orgc` (`event_orgc`),
    UNIQUE INDEX `event_uuid` (`event_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_delegations` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `org_id` bigint NOT NULL,
    `requester_org_id` bigint NOT NULL,
    `event_id` bigint NOT NULL,
    `message` text DEFAULT NULL,
    `distribution` tinyint DEFAULT -1 NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `event_id` (`event_id`),
    INDEX `org_id` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_graph` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `event_id` bigint NOT NULL,
    `user_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `network_name` varchar(255) DEFAULT NULL,
    `network_json` mediumtext NOT NULL,
    `preview_img` mediumtext DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `event_id` (`event_id`),
    INDEX `org_id` (`org_id`),
    INDEX `timestamp` (`timestamp`),
    INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_locks` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `event_id` bigint NOT NULL,
    `user_id` bigint NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `event_id` (`event_id`),
    INDEX `timestamp` (`timestamp`),
    INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_reports` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `event_id` bigint NOT NULL,
    `name` varchar(255) NOT NULL,
    `content` mediumtext DEFAULT NULL,
    `distribution` tinyint DEFAULT 0 NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `timestamp` bigint NOT NULL,
    `deleted` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `event_id` (`event_id`),
    INDEX `name` (`name`),
    UNIQUE INDEX `u_uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_report_tags` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `event_report_id` bigint NOT NULL,
    `tag_id` bigint NOT NULL,
    `local` tinyint(1) DEFAULT '0' NOT NULL,
    `relationship_type` varchar(191) DEFAULT '',
    PRIMARY KEY (`id`),
    INDEX `event_report_id` (`event_report_id`),
    INDEX `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_report_template_variables` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(191) NOT NULL,
    `value` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_tags` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `event_id` bigint NOT NULL,
    `tag_id` bigint NOT NULL,
    `local` tinyint(1) DEFAULT '0' NOT NULL,
    `relationship_type` varchar(191) DEFAULT '',
    PRIMARY KEY (`id`),
    INDEX `idx_event_tags_event_tag` (`event_id`, `tag_id`),
    INDEX `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_templates` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `name` varchar(255) NOT NULL,
    `description` text DEFAULT NULL,
    `org_id` bigint NOT NULL,
    `creator_user_id` bigint NOT NULL,
    `distribution` tinyint DEFAULT 0 NOT NULL,
    `active` tinyint(1) DEFAULT '1' NOT NULL,
    `misp_default` tinyint(1) DEFAULT '0' NOT NULL,
    `exposed` tinyint(1) DEFAULT '0' NOT NULL,
    `version` int UNSIGNED DEFAULT 1 NOT NULL,
    `definition` mediumtext NOT NULL,
    `created` datetime NOT NULL,
    `modified` datetime NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `active` (`active`),
    INDEX `exposed` (`exposed`),
    INDEX `name` (`name`),
    INDEX `org_id` (`org_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `event_template_object_dependencies` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `event_template_id` bigint NOT NULL,
    `object_template_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `object_template_name` varchar(255) NOT NULL,
    `minimum_version` int UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `event_template_id` (`event_template_id`),
    INDEX `object_template_uuid` (`object_template_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `favourite_tags` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `tag_id` bigint NOT NULL,
    `user_id` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `tag_id` (`tag_id`),
    INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `feeds` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `provider` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `rules` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `enabled` tinyint(1) DEFAULT '0',
    `distribution` tinyint DEFAULT 0 NOT NULL,
    `sharing_group_id` bigint DEFAULT 0 NOT NULL,
    `tag_id` bigint DEFAULT 0 NOT NULL,
    `default` tinyint(1) DEFAULT '0',
    `source_format` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT 'misp',
    `fixed_event` tinyint(1) DEFAULT '0' NOT NULL,
    `delta_merge` tinyint(1) DEFAULT '0' NOT NULL,
    `event_id` bigint DEFAULT 0 NOT NULL,
    `publish` tinyint(1) DEFAULT '0' NOT NULL,
    `override_ids` tinyint(1) DEFAULT '0' NOT NULL,
    `settings` text DEFAULT NULL,
    `input_source` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT 'network' NOT NULL,
    `delete_local_file` tinyint(1) DEFAULT '0',
    `lookup_visible` tinyint(1) DEFAULT '0',
    `headers` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `caching_enabled` tinyint(1) DEFAULT '0' NOT NULL,
    `force_to_ids` tinyint(1) DEFAULT '0' NOT NULL,
    `orgc_id` bigint DEFAULT 0 NOT NULL,
    `tag_collection_id` bigint DEFAULT 0 NOT NULL,
    `lock_events` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `input_source` (`input_source`),
    INDEX `orgc_id` (`orgc_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `fuzzy_correlate_ssdeep` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `chunk` varchar(12) NOT NULL,
    `attribute_id` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `attribute_id` (`attribute_id`),
    INDEX `chunk` (`chunk`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `galaxies` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '' NOT NULL,
    `type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `version` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `icon` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '' NOT NULL,
    `namespace` varchar(255) DEFAULT 'misp' NOT NULL,
    `category` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `sub_category` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `enabled` tinyint(1) DEFAULT '1' NOT NULL,
    `local_only` tinyint(1) DEFAULT '0' NOT NULL,
    `kill_chain_order` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `default` tinyint(1) DEFAULT '0' NOT NULL,
    `org_id` bigint NOT NULL,
    `orgc_id` bigint NOT NULL,
    `created` datetime NOT NULL,
    `modified` datetime NOT NULL,
    `distribution` tinyint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `name` (`name`),
    INDEX `namespace` (`namespace`),
    INDEX `type` (`type`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `galaxy_clusters` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(255) CHARACTER SET ascii COLLATE ascii_bin DEFAULT '' NOT NULL,
    `collection_uuid` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `value` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `tag_name` varchar(255) DEFAULT '' NOT NULL,
    `description` text DEFAULT NULL,
    `galaxy_id` bigint NOT NULL,
    `source` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '' NOT NULL,
    `authors` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `version` int DEFAULT 0,
    `distribution` tinyint DEFAULT 0 NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `org_id` bigint NOT NULL,
    `orgc_id` bigint NOT NULL,
    `default` tinyint(1) DEFAULT '0' NOT NULL,
    `locked` tinyint(1) DEFAULT '0' NOT NULL,
    `extends_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT '',
    `extends_version` int DEFAULT 0,
    `published` tinyint(1) DEFAULT '0' NOT NULL,
    `deleted` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `collection_uuid` (`collection_uuid`),
    INDEX `default` (`default`),
    INDEX `extends_uuid` (`extends_uuid`),
    INDEX `extends_version` (`extends_version`),
    INDEX `galaxy_id` (`galaxy_id`),
    INDEX `org_id` (`org_id`),
    INDEX `orgc_id` (`orgc_id`),
    INDEX `sharing_group_id` (`sharing_group_id`),
    INDEX `tag_name` (`tag_name`),
    INDEX `type` (`type`),
    INDEX `uuid` (`uuid`),
    INDEX `value` (`value`(255)),
    INDEX `version` (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `galaxy_cluster_blocklists` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `cluster_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` datetime NOT NULL,
    `cluster_info` text NOT NULL,
    `comment` text DEFAULT NULL,
    `cluster_orgc` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `cluster_orgc` (`cluster_orgc`),
    INDEX `cluster_uuid` (`cluster_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `galaxy_cluster_relations` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `galaxy_cluster_id` bigint NOT NULL,
    `referenced_galaxy_cluster_id` bigint NOT NULL,
    `referenced_galaxy_cluster_uuid` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `referenced_galaxy_cluster_type` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `galaxy_cluster_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `distribution` tinyint DEFAULT 0 NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `default` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `default` (`default`),
    INDEX `galaxy_cluster_id` (`galaxy_cluster_id`),
    INDEX `galaxy_cluster_uuid` (`galaxy_cluster_uuid`),
    INDEX `referenced_galaxy_cluster_id` (`referenced_galaxy_cluster_id`),
    INDEX `referenced_galaxy_cluster_type` (`referenced_galaxy_cluster_type`(255)),
    INDEX `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `galaxy_cluster_relation_tags` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `galaxy_cluster_relation_id` bigint NOT NULL,
    `tag_id` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `galaxy_cluster_relation_id` (`galaxy_cluster_relation_id`),
    INDEX `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `galaxy_elements` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `galaxy_cluster_id` bigint NOT NULL,
    `key` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '' NOT NULL,
    `value` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `galaxy_cluster_id` (`galaxy_cluster_id`),
    INDEX `key` (`key`),
    INDEX `value` (`value`(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `inbox` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `title` varchar(191) NOT NULL,
    `type` varchar(191) NOT NULL,
    `ip` varchar(191) NOT NULL,
    `user_agent` text DEFAULT NULL,
    `user_agent_sha256` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `comment` text DEFAULT NULL,
    `deleted` tinyint(1) DEFAULT '0' NOT NULL,
    `timestamp` bigint NOT NULL,
    `store_as_file` tinyint(1) DEFAULT '0' NOT NULL,
    `data` longtext DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `ip` (`ip`),
    INDEX `timestamp` (`timestamp`),
    INDEX `title` (`title`),
    INDEX `type` (`type`),
    INDEX `user_agent_sha256` (`user_agent_sha256`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `jobs` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `worker` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `job_type` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `job_input` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `status` tinyint DEFAULT 0 NOT NULL,
    `retries` int DEFAULT 0 NOT NULL,
    `message` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `progress` int DEFAULT 0 NOT NULL,
    `org_id` bigint DEFAULT 0 NOT NULL,
    `process_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `date_created` datetime NOT NULL,
    `date_modified` datetime NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `logs` (
    `id` int NOT NULL AUTO_INCREMENT,
    `title` text DEFAULT NULL,
    `created` datetime NOT NULL,
    `model` varchar(80) NOT NULL,
    `model_id` int NOT NULL,
    `action` varchar(20) NOT NULL,
    `user_id` int NOT NULL,
    `change` text DEFAULT NULL,
    `email` varchar(255) DEFAULT '' NOT NULL,
    `org` varchar(255) DEFAULT '' NOT NULL,
    `description` text DEFAULT NULL,
    `ip` varchar(45) DEFAULT '' NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;

CREATE TABLE `news` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `message` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `title` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `user_id` bigint NOT NULL,
    `date_created` bigint NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `notes` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `object_sha256` varchar(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    `authors` text DEFAULT NULL,
    `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` datetime NOT NULL,
    `modified` datetime NOT NULL,
    `distribution` tinyint NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `locked` tinyint(1) DEFAULT '0' NOT NULL,
    `note` mediumtext DEFAULT NULL,
    `language` varchar(16) DEFAULT 'en',
    PRIMARY KEY (`id`),
    INDEX `distribution` (`distribution`),
    INDEX `object_sha256` (`object_sha256`),
    INDEX `object_type` (`object_type`),
    INDEX `object_uuid` (`object_uuid`),
    INDEX `org_uuid` (`org_uuid`),
    INDEX `orgc_uuid` (`orgc_uuid`),
    INDEX `sharing_group_id` (`sharing_group_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `noticelists` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) NOT NULL,
    `expanded_name` text NOT NULL,
    `ref` text DEFAULT NULL,
    `geographical_area` varchar(255) DEFAULT NULL,
    `version` int DEFAULT 1 NOT NULL,
    `enabled` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `geographical_area` (`geographical_area`),
    INDEX `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `noticelist_entries` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `noticelist_id` bigint NOT NULL,
    `data` text NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `noticelist_id` (`noticelist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `notification_logs` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `org_id` bigint NOT NULL,
    `type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `org_id` (`org_id`),
    INDEX `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `no_acl_correlations` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `attribute_id` bigint NOT NULL,
    `1_attribute_id` bigint NOT NULL,
    `event_id` bigint NOT NULL,
    `1_event_id` bigint NOT NULL,
    `value_id` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `1_event_id` (`1_event_id`),
    INDEX `idx_nac_1attr_1evt` (`1_attribute_id`, `1_event_id`),
    INDEX `idx_nac_attr_evt` (`attribute_id`, `event_id`),
    INDEX `idx_nac_evt_1evt` (`event_id`, `1_event_id`),
    INDEX `idx_nac_val_1attr` (`value_id`, `1_attribute_id`),
    INDEX `idx_nac_val_attr` (`value_id`, `attribute_id`),
    UNIQUE INDEX `unique_correlation` (`attribute_id`, `1_attribute_id`, `value_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `objects` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) DEFAULT NULL,
    `meta-category` varchar(255) DEFAULT NULL,
    `description` text DEFAULT NULL,
    `template_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `template_version` int NOT NULL,
    `event_id` bigint NOT NULL,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `distribution` tinyint DEFAULT 0 NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `comment` text NOT NULL,
    `deleted` tinyint(1) DEFAULT '0' NOT NULL,
    `first_seen` bigint DEFAULT NULL,
    `last_seen` bigint DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `first_seen` (`first_seen`),
    INDEX `idx_event_deleted_name` (`event_id`, `deleted`, `name`),
    INDEX `idx_obj_acl` (`event_id`, `distribution`, `sharing_group_id`, `deleted`),
    INDEX `idx_obj_id_acl` (`id`, `event_id`, `distribution`),
    INDEX `idx_obj_meta` (`meta-category`, `timestamp`),
    INDEX `last_seen` (`last_seen`),
    INDEX `name` (`name`),
    INDEX `template_uuid` (`template_uuid`),
    INDEX `template_version` (`template_version`),
    INDEX `timestamp` (`timestamp`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `object_references` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `object_id` bigint NOT NULL,
    `event_id` bigint NOT NULL,
    `source_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `referenced_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `referenced_id` bigint NOT NULL,
    `referenced_type` int DEFAULT 0 NOT NULL,
    `relationship_type` varchar(255) DEFAULT NULL,
    `comment` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `deleted` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `event_id` (`event_id`),
    INDEX `object_id` (`object_id`),
    INDEX `referenced_id` (`referenced_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `object_relationships` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `version` int NOT NULL,
    `name` varchar(255) DEFAULT NULL,
    `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `format` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `highlighted` tinyint(1) DEFAULT '0',
    PRIMARY KEY (`id`),
    INDEX `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `object_templates` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `user_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `name` varchar(255) DEFAULT NULL,
    `meta-category` varchar(255) DEFAULT NULL,
    `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `version` int NOT NULL,
    `requirements` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `fixed` tinyint(1) DEFAULT '0' NOT NULL,
    `active` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `meta-category` (`meta-category`),
    INDEX `name` (`name`),
    INDEX `org_id` (`org_id`),
    INDEX `user_id` (`user_id`),
    INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `object_template_elements` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `object_template_id` bigint NOT NULL,
    `object_relation` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `ui-priority` int NOT NULL,
    `categories` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `sane_default` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `values_list` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `disable_correlation` tinyint(1) DEFAULT NULL,
    `multiple` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `object_relation` (`object_relation`),
    INDEX `object_template_id` (`object_template_id`),
    INDEX `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `opinions` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `object_sha256` varchar(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    `authors` text DEFAULT NULL,
    `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` datetime NOT NULL,
    `modified` datetime NOT NULL,
    `distribution` tinyint NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `locked` tinyint(1) DEFAULT '0' NOT NULL,
    `opinion` int UNSIGNED DEFAULT NULL,
    `comment` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `distribution` (`distribution`),
    INDEX `object_sha256` (`object_sha256`),
    INDEX `object_type` (`object_type`),
    INDEX `object_uuid` (`object_uuid`),
    INDEX `opinion` (`opinion`),
    INDEX `org_uuid` (`org_uuid`),
    INDEX `orgc_uuid` (`orgc_uuid`),
    INDEX `sharing_group_id` (`sharing_group_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `organisations` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '' NOT NULL,
    `date_created` datetime NOT NULL,
    `date_modified` datetime NOT NULL,
    `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '' NOT NULL,
    `nationality` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '' NOT NULL,
    `sector` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '' NOT NULL,
    `created_by` bigint DEFAULT 0 NOT NULL,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `contacts` text DEFAULT NULL,
    `local` tinyint(1) DEFAULT '0' NOT NULL,
    `restricted_to_domain` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `landingpage` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `name` (`name`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `org_blocklists` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` datetime NOT NULL,
    `org_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `comment` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `org_name` (`org_name`),
    UNIQUE INDEX `org_uuid` (`org_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `over_correlating_values` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `value_id` bigint DEFAULT NULL,
    `occurrence` int UNSIGNED DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `occurrence` (`occurrence`),
    UNIQUE INDEX `value_id` (`value_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `regexp` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `regexp` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `replacement` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `type` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT 'ALL' NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `relationships` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `object_sha256` varchar(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    `authors` text DEFAULT NULL,
    `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` datetime NOT NULL,
    `modified` datetime NOT NULL,
    `distribution` tinyint NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `locked` tinyint(1) DEFAULT '0' NOT NULL,
    `relationship_type` varchar(255) DEFAULT NULL,
    `related_object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `related_object_sha256` varchar(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `related_object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `distribution` (`distribution`),
    INDEX `object_sha256` (`object_sha256`),
    INDEX `object_type` (`object_type`),
    INDEX `object_uuid` (`object_uuid`),
    INDEX `org_uuid` (`org_uuid`),
    INDEX `orgc_uuid` (`orgc_uuid`),
    INDEX `related_object_sha256` (`related_object_sha256`),
    INDEX `related_object_type` (`related_object_type`),
    INDEX `related_object_uuid` (`related_object_uuid`),
    INDEX `relationship_type` (`relationship_type`),
    INDEX `sharing_group_id` (`sharing_group_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `rest_client_histories` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `org_id` bigint NOT NULL,
    `user_id` bigint NOT NULL,
    `headers` text DEFAULT NULL,
    `body` text DEFAULT NULL,
    `url` text DEFAULT NULL,
    `http_method` varchar(255) DEFAULT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `use_full_path` tinyint(1) DEFAULT '0',
    `show_result` tinyint(1) DEFAULT '0',
    `skip_ssl` tinyint(1) DEFAULT '0',
    `outcome` int NOT NULL,
    `bookmark` tinyint(1) DEFAULT '0' NOT NULL,
    `bookmark_name` varchar(255) DEFAULT '',
    PRIMARY KEY (`id`),
    INDEX `org_id` (`org_id`),
    INDEX `timestamp` (`timestamp`),
    INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `roles` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `created` datetime DEFAULT NULL,
    `modified` datetime DEFAULT NULL,
    `perm_add` tinyint(1) DEFAULT NULL,
    `perm_modify` tinyint(1) DEFAULT NULL,
    `perm_modify_org` tinyint(1) DEFAULT NULL,
    `perm_publish` tinyint(1) DEFAULT NULL,
    `perm_delegate` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_sync` tinyint(1) DEFAULT NULL,
    `perm_admin` tinyint(1) DEFAULT NULL,
    `perm_audit` tinyint(1) DEFAULT NULL,
    `perm_full` tinyint(1) DEFAULT NULL,
    `perm_auth` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_site_admin` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_regexp_access` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_tagger` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_template` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_sharing_group` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_tag_editor` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_sighting` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_object_template` tinyint(1) DEFAULT '0' NOT NULL,
    `default_role` tinyint(1) DEFAULT '0' NOT NULL,
    `memory_limit` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '',
    `max_execution_time` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '',
    `restricted_to_site_admin` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_publish_zmq` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_publish_kafka` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_decaying` tinyint(1) DEFAULT '0' NOT NULL,
    `enforce_rate_limit` tinyint(1) DEFAULT '0' NOT NULL,
    `rate_limit_count` int DEFAULT 0 NOT NULL,
    `perm_galaxy_editor` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_warninglist` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_view_feed_correlations` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_analyst_data` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_skip_otp` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_server_sign` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_sync_internal` tinyint(1) DEFAULT '0' NOT NULL,
    `perm_sync_authoritative` tinyint(1) DEFAULT '0' NOT NULL,
    `restsearch_limit_result` int DEFAULT 0,
    `perm_ai_tools` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `scheduled_tasks` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `type` varchar(100) NOT NULL,
    `timer` int NOT NULL,
    `last_job_id` bigint DEFAULT NULL,
    `description` varchar(255) NOT NULL,
    `next_execution_time` bigint NOT NULL,
    `message` varchar(255) NOT NULL,
    `user_id` bigint NOT NULL,
    `action` varchar(40) NOT NULL,
    `params` varchar(255) DEFAULT NULL,
    `enabled` tinyint(1) DEFAULT '0',
    `last_run_at` bigint DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `schema_migrations` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `migration_id` varchar(191) NOT NULL,
    `applied_at` datetime NOT NULL,
    `duration_ms` int DEFAULT 0 NOT NULL,
    `status` varchar(16) DEFAULT 'applied' NOT NULL,
    `error` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `migration_id` (`migration_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `servers` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `authkey` varbinary(255) NOT NULL,
    `org_id` bigint NOT NULL,
    `push` tinyint(1) NOT NULL,
    `pull` tinyint(1) NOT NULL,
    `push_sightings` tinyint(1) DEFAULT '0' NOT NULL,
    `push_galaxy_clusters` tinyint(1) DEFAULT '0' NOT NULL,
    `push_analyst_data` tinyint(1) DEFAULT '0' NOT NULL,
    `pull_analyst_data` tinyint(1) DEFAULT '0' NOT NULL,
    `pull_galaxy_clusters` tinyint(1) DEFAULT '0' NOT NULL,
    `push_collections` tinyint(1) DEFAULT '0' NOT NULL,
    `pull_collections` tinyint(1) DEFAULT '0' NOT NULL,
    `lastpulledid` bigint DEFAULT NULL,
    `lastpushedid` bigint DEFAULT NULL,
    `organization` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `remote_org_id` bigint NOT NULL,
    `publish_without_email` tinyint(1) DEFAULT '0' NOT NULL,
    `unpublish_event` tinyint(1) DEFAULT '0' NOT NULL,
    `self_signed` tinyint(1) NOT NULL,
    `pull_rules` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `push_rules` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `cert_file` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `client_cert_file` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `internal` tinyint(1) DEFAULT '0' NOT NULL,
    `skip_proxy` tinyint(1) DEFAULT '0' NOT NULL,
    `remove_missing_tags` tinyint(1) DEFAULT '0' NOT NULL,
    `caching_enabled` tinyint(1) DEFAULT '0' NOT NULL,
    `priority` int DEFAULT 0 NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `org_id` (`org_id`),
    INDEX `priority` (`priority`),
    INDEX `remote_org_id` (`remote_org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `shadow_attributes` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `old_id` bigint DEFAULT 0,
    `event_id` bigint NOT NULL,
    `type` varchar(100) NOT NULL,
    `category` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `to_ids` tinyint(1) DEFAULT '1' NOT NULL,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `value1_id` bigint DEFAULT NULL,
    `value2_id` bigint DEFAULT NULL,
    `org_id` bigint NOT NULL,
    `email` varchar(255) DEFAULT NULL,
    `event_org_id` bigint NOT NULL,
    `comment` text NOT NULL,
    `event_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `deleted` tinyint(1) DEFAULT '0' NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `proposal_to_delete` tinyint(1) DEFAULT '0' NOT NULL,
    `disable_correlation` tinyint(1) DEFAULT '0' NOT NULL,
    `first_seen` bigint DEFAULT NULL,
    `last_seen` bigint DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `category` (`category`),
    INDEX `event_id` (`event_id`),
    INDEX `event_org_id` (`event_org_id`),
    INDEX `event_uuid` (`event_uuid`),
    INDEX `first_seen` (`first_seen`),
    INDEX `last_seen` (`last_seen`),
    INDEX `old_id` (`old_id`),
    INDEX `type` (`type`),
    INDEX `uuid` (`uuid`),
    INDEX `value1_id` (`value1_id`),
    INDEX `value2_id` (`value2_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `sharing_groups` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) NOT NULL,
    `releasability` text NOT NULL,
    `description` text NOT NULL,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `organisation_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `org_id` bigint NOT NULL,
    `sync_user_id` bigint DEFAULT 0 NOT NULL,
    `active` tinyint(1) NOT NULL,
    `created` datetime NOT NULL,
    `modified` datetime NOT NULL,
    `local` tinyint(1) NOT NULL,
    `roaming` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `name` (`name`),
    INDEX `org_id` (`org_id`),
    INDEX `organisation_uuid` (`organisation_uuid`),
    INDEX `sync_user_id` (`sync_user_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `sharing_group_blueprints` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `name` varchar(191) NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `user_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    `sharing_group_id` bigint DEFAULT NULL,
    `rules` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `name` (`name`),
    INDEX `org_id` (`org_id`),
    INDEX `sharing_group_id` (`sharing_group_id`),
    INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `sharing_group_orgs` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `sharing_group_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    `extend` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `org_id` (`org_id`),
    INDEX `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `sharing_group_servers` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `sharing_group_id` bigint NOT NULL,
    `server_id` bigint NOT NULL,
    `all_orgs` tinyint(1) NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `server_id` (`server_id`),
    INDEX `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `sightingdbs` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) NOT NULL,
    `description` text DEFAULT NULL,
    `owner` varchar(255) DEFAULT '',
    `host` varchar(255) DEFAULT 'http://localhost',
    `port` int DEFAULT 9999,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `enabled` tinyint(1) DEFAULT '0' NOT NULL,
    `skip_proxy` tinyint(1) DEFAULT '0' NOT NULL,
    `ssl_skip_verification` tinyint(1) DEFAULT '0' NOT NULL,
    `namespace` varchar(255) DEFAULT '',
    PRIMARY KEY (`id`),
    INDEX `host` (`host`),
    INDEX `name` (`name`),
    INDEX `owner` (`owner`),
    INDEX `port` (`port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `sightingdb_orgs` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `sightingdb_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `org_id` (`org_id`),
    INDEX `sightingdb_id` (`sightingdb_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `sightings` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `attribute_id` bigint NOT NULL,
    `event_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    `date_sighting` bigint NOT NULL,
    `uuid` varchar(255) CHARACTER SET ascii COLLATE ascii_bin DEFAULT '',
    `source` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '',
    `type` int DEFAULT 0,
    PRIMARY KEY (`id`),
    INDEX `attribute_id` (`attribute_id`),
    INDEX `event_id` (`event_id`),
    INDEX `org_id` (`org_id`),
    INDEX `source` (`source`),
    INDEX `type` (`type`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `sighting_blocklists` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `created` datetime NOT NULL,
    `org_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `comment` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `org_name` (`org_name`),
    INDEX `org_uuid` (`org_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `system_settings` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `setting` varchar(255) NOT NULL,
    `value` blob NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `setting` (`setting`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `tags` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) NOT NULL,
    `colour` varchar(7) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `exportable` tinyint(1) NOT NULL,
    `org_id` bigint DEFAULT 0 NOT NULL,
    `user_id` bigint DEFAULT 0 NOT NULL,
    `hide_tag` tinyint(1) DEFAULT '0' NOT NULL,
    `numerical_value` int DEFAULT NULL,
    `is_galaxy` tinyint(1) DEFAULT '0' NOT NULL,
    `is_custom_galaxy` tinyint(1) DEFAULT '0' NOT NULL,
    `local_only` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `name` (`name`),
    INDEX `numerical_value` (`numerical_value`),
    INDEX `org_id` (`org_id`),
    INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `tag_collections` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `user_id` bigint NOT NULL,
    `org_id` bigint NOT NULL,
    `name` varchar(255) NOT NULL,
    `description` text NOT NULL,
    `all_orgs` tinyint(1) DEFAULT '0' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `org_id` (`org_id`),
    INDEX `user_id` (`user_id`),
    UNIQUE INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `tag_collection_tags` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `tag_collection_id` bigint NOT NULL,
    `tag_id` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `tag_collection_id` (`tag_collection_id`),
    INDEX `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `taxii_servers` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `name` varchar(191) NOT NULL,
    `owner` varchar(191) NOT NULL,
    `discovery_url` varchar(512) DEFAULT NULL,
    `api_root` varchar(1024) DEFAULT NULL,
    `description` text DEFAULT NULL,
    `filters` text DEFAULT NULL,
    `api_key` text NOT NULL,
    `auth_type` varchar(191) DEFAULT 'basic',
    `collection` varchar(40) DEFAULT NULL,
    `skip_proxy` tinyint(1) DEFAULT '0' NOT NULL,
    `enabled` tinyint(1) DEFAULT '1' NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `baseurl` (`discovery_url`),
    INDEX `name` (`name`),
    INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `taxonomies` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `namespace` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `version` int NOT NULL,
    `enabled` tinyint(1) DEFAULT '0' NOT NULL,
    `exclusive` tinyint(1) DEFAULT '0',
    `required` tinyint(1) DEFAULT '0' NOT NULL,
    `highlighted` tinyint(1) DEFAULT '0',
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `taxonomy_entries` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `taxonomy_predicate_id` bigint NOT NULL,
    `value` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `expanded` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `colour` varchar(7) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `numerical_value` int DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `numerical_value` (`numerical_value`),
    INDEX `taxonomy_predicate_id` (`taxonomy_predicate_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `taxonomy_predicates` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `taxonomy_id` bigint NOT NULL,
    `value` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `expanded` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `colour` varchar(7) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `exclusive` tinyint(1) DEFAULT '0',
    `numerical_value` int DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `numerical_value` (`numerical_value`),
    INDEX `taxonomy_id` (`taxonomy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `threat_levels` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(50) NOT NULL,
    `description` varchar(255) DEFAULT NULL,
    `form_description` varchar(255) NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `users` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `org_id` bigint NOT NULL,
    `server_id` bigint DEFAULT 0 NOT NULL,
    `email` varchar(255) NOT NULL,
    `autoalert` tinyint(1) DEFAULT '0' NOT NULL,
    `authkey` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
    `invited_by` bigint DEFAULT 0 NOT NULL,
    `gpgkey` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `certif_public` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `nids_sid` int DEFAULT 0 NOT NULL,
    `termsaccepted` tinyint(1) DEFAULT '0' NOT NULL,
    `newsread` bigint DEFAULT 0,
    `role_id` bigint DEFAULT 0 NOT NULL,
    `change_pw` tinyint(1) DEFAULT '0' NOT NULL,
    `contactalert` tinyint(1) DEFAULT '0' NOT NULL,
    `disabled` tinyint(1) DEFAULT '0' NOT NULL,
    `expiration` datetime DEFAULT NULL,
    `current_login` bigint DEFAULT 0,
    `last_login` bigint DEFAULT 0,
    `force_logout` tinyint(1) DEFAULT '0' NOT NULL,
    `date_created` bigint DEFAULT NULL,
    `date_modified` bigint DEFAULT NULL,
    `sub` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `external_auth_required` tinyint(1) DEFAULT '0' NOT NULL,
    `external_auth_key` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `last_api_access` bigint DEFAULT 0,
    `notification_daily` tinyint(1) DEFAULT '0' NOT NULL,
    `notification_weekly` tinyint(1) DEFAULT '0' NOT NULL,
    `notification_monthly` tinyint(1) DEFAULT '0' NOT NULL,
    `totp` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
    `hotp_counter` int DEFAULT NULL,
    `last_pw_change` bigint DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `email` (`email`),
    INDEX `org_id` (`org_id`),
    INDEX `server_id` (`server_id`),
    UNIQUE INDEX `sub` (`sub`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `user_login_profiles` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `created_at` datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
    `user_id` bigint NOT NULL,
    `status` varchar(191) DEFAULT NULL,
    `ip` varchar(191) DEFAULT NULL,
    `user_agent` varchar(191) DEFAULT NULL,
    `accept_lang` varchar(191) DEFAULT NULL,
    `geoip` varchar(191) DEFAULT NULL,
    `ua_platform` varchar(191) DEFAULT NULL,
    `ua_browser` varchar(191) DEFAULT NULL,
    `ua_pattern` varchar(191) DEFAULT NULL,
    `hash` varchar(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `geoip` (`geoip`),
    UNIQUE INDEX `hash` (`hash`),
    INDEX `ip` (`ip`),
    INDEX `status` (`status`),
    INDEX `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `user_settings` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `setting` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `value` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `user_id` bigint NOT NULL,
    `timestamp` bigint NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `setting` (`setting`),
    UNIQUE INDEX `unique_setting` (`user_id`, `setting`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `value_enrichment_runs` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `org_id` bigint NOT NULL,
    `value_hash` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `value` text DEFAULT NULL,
    `module` varchar(100) NOT NULL,
    `type` varchar(100) NOT NULL,
    `state` varchar(32) NOT NULL,
    `user_id` bigint DEFAULT NULL,
    `last_run` bigint DEFAULT 0 NOT NULL,
    `took` int DEFAULT 0 NOT NULL,
    `total` int DEFAULT 0 NOT NULL,
    `shown` int DEFAULT 0 NOT NULL,
    `capped` tinyint(1) DEFAULT '0' NOT NULL,
    `message` text DEFAULT NULL,
    `result` longblob DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `last_run` (`last_run`),
    UNIQUE INDEX `run` (`org_id`, `value_hash`, `module`, `type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `value_ip_ranges` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `value_id` bigint NOT NULL,
    `ip_start` varbinary(16) NOT NULL,
    `ip_end` varbinary(16) NOT NULL,
    `prefix` tinyint UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `start_end` (`ip_start`, `ip_end`, `value_id`),
    UNIQUE INDEX `value_id` (`value_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `warninglists` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT 'string' NOT NULL,
    `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `version` int DEFAULT 1 NOT NULL,
    `enabled` tinyint(1) DEFAULT '0' NOT NULL,
    `default` tinyint(1) DEFAULT '1' NOT NULL,
    `category` varchar(20) DEFAULT 'false_positive' NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `warninglist_entries` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `value` text NOT NULL,
    `warninglist_id` bigint NOT NULL,
    `comment` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `idx_warn_values` (`value`(64)),
    INDEX `idx_wle_list_value` (`warninglist_id`, `value`(191)),
    INDEX `warninglist_id` (`warninglist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `warninglist_types` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `warninglist_id` bigint NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `workflows` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `name` varchar(191) NOT NULL,
    `description` varchar(191) NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `enabled` tinyint(1) DEFAULT '0' NOT NULL,
    `counter` int DEFAULT 0 NOT NULL,
    `trigger_id` varchar(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `debug_enabled` tinyint(1) DEFAULT '0' NOT NULL,
    `data` longtext DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `name` (`name`),
    INDEX `timestamp` (`timestamp`),
    INDEX `trigger_id` (`trigger_id`),
    INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE `workflow_blueprints` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    `name` varchar(191) NOT NULL,
    `description` varchar(191) NOT NULL,
    `timestamp` bigint DEFAULT 0 NOT NULL,
    `default` tinyint(1) DEFAULT '0' NOT NULL,
    `data` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `name` (`name`),
    INDEX `timestamp` (`timestamp`),
    INDEX `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

-- --------------------------------------------------------

--
-- Default values for initial installation
--

INSERT IGNORE INTO `admin_settings` (`id`, `setting`, `value`) VALUES (1, 'db_version', '159');
INSERT IGNORE INTO `admin_settings` (`id`, `setting`, `value`) VALUES (8, 'fix_login', UNIX_TIMESTAMP());
INSERT IGNORE INTO `admin_settings` (`id`, `setting`, `value`) VALUES (9, 'default_role', '3');

INSERT IGNORE INTO `feeds` (`id`, `name`, `provider`, `url`, `rules`, `enabled`, `distribution`, `sharing_group_id`, `tag_id`, `default`, `source_format`, `fixed_event`, `delta_merge`, `event_id`, `publish`, `override_ids`, `settings`, `input_source`, `delete_local_file`, `lookup_visible`, `headers`, `caching_enabled`, `force_to_ids`, `orgc_id`, `tag_collection_id`, `lock_events`) VALUES
(1, 'CIRCL OSINT Feed', 'CIRCL', 'https://www.circl.lu/doc/misp/feed-osint', NULL, '0', 3, 0, 0, '1', 'misp', '0', '0', 0, '0', '0', NULL, 'network', '0', '0', NULL, '0', '0', 0, 0, '0'),
(2, 'The Botvrij.eu Data', 'Botvrij.eu', 'https://www.botvrij.eu/data/feed-osint', NULL, '0', 3, 0, 0, '1', 'misp', '0', '0', 0, '0', '0', NULL, 'network', '0', '0', NULL, '0', '0', 0, 0, '0');

INSERT IGNORE INTO `regexp` (`id`, `regexp`, `replacement`, `type`) VALUES
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

INSERT IGNORE INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_delegate`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_site_admin`, `perm_regexp_access`, `perm_tagger`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_sighting`, `perm_object_template`, `default_role`, `memory_limit`, `max_execution_time`, `restricted_to_site_admin`, `perm_publish_zmq`, `perm_publish_kafka`, `perm_decaying`, `enforce_rate_limit`, `rate_limit_count`, `perm_galaxy_editor`, `perm_warninglist`, `perm_view_feed_correlations`, `perm_analyst_data`, `perm_skip_otp`, `perm_server_sign`, `perm_sync_internal`, `perm_sync_authoritative`, `restsearch_limit_result`, `perm_ai_tools`) VALUES
(1, 'admin', NOW(), NOW(), '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '0', NULL, NULL, '0', '1', '1', '1', '0', 0, '1', '1', '1', '1', '0', '1', '0', '0', 0, '1'),
(2, 'Org Admin', NOW(), NOW(), '1', '1', '1', '1', '1', '0', '1', '1', '0', '1', '0', '0', '1', '1', '1', '1', '1', '0', '0', NULL, NULL, '0', '1', '1', '1', '0', 0, '1', '0', '0', '1', '0', '0', '0', '0', 0, '0'),
(3, 'User', NOW(), NOW(), '1', '1', '1', '0', '0', '0', '0', '1', '0', '1', '0', '0', '1', '0', '0', '0', '1', '0', '1', NULL, NULL, '0', '0', '0', '1', '0', 0, '1', '0', '0', '1', '0', '0', '0', '0', 0, '0'),
(4, 'Publisher', NOW(), NOW(), '1', '1', '1', '1', '1', '0', '0', '1', '0', '1', '0', '0', '1', '0', '0', '0', '1', '0', '0', NULL, NULL, '0', '1', '1', '1', '0', 0, '1', '0', '0', '1', '0', '0', '0', '0', 0, '0'),
(5, 'Sync user', NOW(), NOW(), '1', '1', '1', '1', '1', '1', '0', '1', '0', '1', '0', '0', '1', '0', '1', '1', '1', '0', '0', NULL, NULL, '0', '1', '1', '1', '0', 0, '1', '0', '0', '1', '0', '0', '0', '0', 0, '0'),
(6, 'Read Only', NOW(), NOW(), '0', '0', '0', '0', '0', '0', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', NULL, NULL, '0', '0', '0', '0', '0', 0, '0', '0', '0', '0', '0', '0', '0', '0', 0, '0');

INSERT IGNORE INTO `threat_levels` (`id`, `name`, `description`, `form_description`) VALUES
(1, 'High', '*high* means sophisticated APT malware or 0-day attack', 'Sophisticated APT malware or 0-day attack'),
(2, 'Medium', '*medium* means APT malware', 'APT malware'),
(3, 'Low', '*low* means mass-malware', 'Mass-malware'),
(4, 'Undefined', '*undefined* no risk', 'No risk');

INSERT IGNORE INTO `org_blocklists` (`id`, `org_uuid`, `created`, `org_name`, `comment`) VALUES
(3, '58d38339-7b24-4386-b4b4-4c0f950d210f', NOW(), 'Setec Astronomy', 'default example'),
(4, '58d38326-eda8-443a-9fa8-4e12950d210f', NOW(), 'Acme Finance', 'default example');

INSERT IGNORE INTO `dashboards` (`id`, `uuid`, `name`, `description`, `default`, `selectable`, `user_id`, `restrict_to_org_id`, `restrict_to_role_id`, `restrict_to_permission_flag`, `value`, `timestamp`) VALUES
(1, '5000487b-3e75-46e4-8c43-96da9dc2268b', 'Administrator', 'A comprehensive site-administrator overview: live resource monitors (CPU, memory, disk), instance usage statistics, system health rollup, sync test and cache freshness, worker queues, mail log, recent logins, API activity, and the latest users to join. Visible to site admins only.', '0', '1', 0, 0, 0, 'perm_site_admin', '[{\"instance_id\":\"w_1\",\"widget\":\"UsageDataWidget\",\"config\":{\"alias\":\"Usage\"},\"position\":{\"x\":2,\"y\":6,\"w\":4,\"h\":3}},{\"instance_id\":\"w_2\",\"widget\":\"NewUsersWidget\",\"config\":{\"alias\":\"Latest users\",\"fields\":[\"id\",\"date_created\",\"Organisation.name\",\"email\"]},\"position\":{\"x\":2,\"y\":0,\"w\":4,\"h\":6}},{\"instance_id\":\"w_5\",\"widget\":\"LoginsWidget\",\"config\":{\"alias\":\"Logins this month\"},\"position\":{\"x\":9,\"y\":4,\"w\":3,\"h\":3}},{\"instance_id\":\"w_6\",\"widget\":\"APIActivityWidget\",\"config\":{\"alias\":\"API activity\",\"filter\":[]},\"position\":{\"x\":9,\"y\":7,\"w\":3,\"h\":3}},{\"instance_id\":\"w_7\",\"widget\":\"BenchmarkTopListWidget\",\"config\":{\"alias\":\"\",\"refresh_delay\":\"\",\"days\":\"10\",\"field\":\"sql_time\"},\"position\":{\"x\":0,\"y\":9,\"w\":3,\"h\":6}},{\"instance_id\":\"w_8\",\"widget\":\"MispAdminSyncTestWidget\",\"config\":[],\"position\":{\"x\":6,\"y\":7,\"w\":3,\"h\":4}},{\"instance_id\":\"w_10\",\"widget\":\"MispAdminWorkerWidget\",\"config\":{\"alias\":\"\",\"refresh_delay\":\"\"},\"position\":{\"x\":9,\"y\":10,\"w\":3,\"h\":5}},{\"instance_id\":\"w_11\",\"widget\":\"CpuLoadMonitorWidget\",\"config\":{\"alias\":\"\",\"window\":180,\"interval\":3},\"position\":{\"x\":0,\"y\":0,\"w\":2,\"h\":3}},{\"instance_id\":\"w_12\",\"widget\":\"MemoryUsageMonitorWidget\",\"config\":{\"alias\":\"\",\"window\":180,\"interval\":3},\"position\":{\"x\":0,\"y\":3,\"w\":2,\"h\":3}},{\"instance_id\":\"w_13\",\"widget\":\"DiskUsageMonitorWidget\",\"config\":{\"path\":\"\",\"threshold\":85},\"position\":{\"x\":0,\"y\":6,\"w\":2,\"h\":3}},{\"instance_id\":\"w_14\",\"widget\":\"LoggedInUsersWidget\",\"config\":[],\"position\":{\"x\":9,\"y\":0,\"w\":3,\"h\":4}},{\"instance_id\":\"w_15\",\"widget\":\"MispAdminHealthWidget\",\"config\":[],\"position\":{\"x\":6,\"y\":0,\"w\":3,\"h\":7}},{\"instance_id\":\"w_16\",\"widget\":\"MispCacheStatusWidget\",\"config\":[],\"position\":{\"x\":6,\"y\":11,\"w\":3,\"h\":4}},{\"instance_id\":\"w_17\",\"widget\":\"MispMailLogWidget\",\"config\":{\"log_path\":\"\",\"limit\":20,\"lookback_bytes\":65536},\"position\":{\"x\":3,\"y\":9,\"w\":3,\"h\":6}}]', 1792347918),
(2, '0c6b496d-b6e7-43f3-be7f-2f30215c568c', 'Analyst', 'A threat-analyst starting point: the geographic spread of recent indicators and of threat-actor origins, a live attack map, ATT&CK technique coverage, trending vulnerabilities and threat actors, new-data stats for your time window, overlap with your organisation\'s data, and the latest analyst notes, opinions, and event reports.', '1', '1', 0, 0, 0, '', '[{\"instance_id\":\"w_3\",\"widget\":\"AttributeGeoMapWidget\",\"config\":{\"alias\":\"Recent geolocated indicators by country\",\"time_window\":\"7d\",\"limit\":10000,\"palette\":\"danger\",\"projection\":\"naturalEarth\",\"sources\":[\"ip\",\"domain_tld\",\"asn\",\"country_galaxy\",\"threat_actor\"]},\"position\":{\"x\":0,\"y\":7,\"w\":3,\"h\":4}},{\"instance_id\":\"w_4\",\"widget\":\"ThreatActorCountryMapWidget\",\"config\":{\"alias\":\"Threat actor origins\"},\"position\":{\"x\":3,\"y\":7,\"w\":3,\"h\":4}},{\"instance_id\":\"w_8\",\"widget\":\"AttackWidget\",\"config\":{\"alias\":\"\",\"time_window\":\"7d\",\"filters\":{\"attackGalaxy\":\"mitre-attack-pattern\",\"published\":[0,1]}},\"position\":{\"x\":0,\"y\":11,\"w\":12,\"h\":6}},{\"instance_id\":\"w_9\",\"widget\":\"TrendingWidget\",\"config\":{\"alias\":\"Trending vulnerabilities\",\"dimension\":\"vulnerability\",\"time_window\":\"7d\",\"threshold\":10,\"min_count\":3},\"position\":{\"x\":10,\"y\":2,\"w\":2,\"h\":5}},{\"instance_id\":\"w_10\",\"widget\":\"NewDataStatsWidget\",\"config\":{\"alias\":\"New data within time window\",\"time_window\":\"7d\",\"country\":\"\",\"sector\":\"\"},\"position\":{\"x\":0,\"y\":0,\"w\":12,\"h\":2}},{\"instance_id\":\"w_12\",\"widget\":\"TrendingWidget\",\"config\":{\"alias\":\"Trending threat actors\",\"dimension\":\"threat-actor\",\"time_window\":\"7d\",\"threshold\":10,\"min_count\":3},\"position\":{\"x\":8,\"y\":2,\"w\":2,\"h\":5}},{\"instance_id\":\"w_13\",\"widget\":\"PewPewMapWidget\",\"config\":{\"alias\":\"\",\"time_window\":\"7d\",\"mode\":\"webgl-globe\",\"skin\":\"day\",\"max_arcs\":500},\"position\":{\"x\":6,\"y\":7,\"w\":2,\"h\":4}},{\"instance_id\":\"w_15\",\"widget\":\"OverlapWithMyOrgWidget\",\"config\":{\"alias\":\"Correlations to my org\'s data\",\"time_window\":\"7d\",\"exclude_own_org\":true},\"position\":{\"x\":8,\"y\":7,\"w\":4,\"h\":4}},{\"instance_id\":\"w_19\",\"widget\":\"RecentAnalystDataWidget\",\"config\":{\"alias\":\"Notes and Opinions\",\"time_window\":\"7d\",\"limit\":10},\"position\":{\"x\":0,\"y\":2,\"w\":4,\"h\":5}},{\"instance_id\":\"w_20\",\"widget\":\"RecentEventReportsWidget\",\"config\":{\"time_window\":\"7d\",\"limit\":10},\"position\":{\"x\":4,\"y\":2,\"w\":4,\"h\":5}}]', 1792347918),
(3, '2b50c003-c475-4c9c-ac90-0a177b44e565', 'Community', 'A sharing-community overview: where the member organisations are, who contributes most (orgs and users), how the community has grown, overall usage, and the sharing relationships between organisations.', '0', '1', 0, 0, 0, '', '[{\"instance_id\":\"w_1\",\"widget\":\"OrganisationMapWidget\",\"config\":{\"alias\":\"Organisations by country\"},\"position\":{\"x\":0,\"y\":0,\"w\":8,\"h\":5}},{\"instance_id\":\"w_2\",\"widget\":\"UsageDataWidget\",\"config\":{\"alias\":\"Usage\"},\"position\":{\"x\":8,\"y\":0,\"w\":4,\"h\":5}},{\"instance_id\":\"w_3\",\"widget\":\"OrgContributionToplistWidget\",\"config\":{\"alias\":\"Top contributing organisations\"},\"position\":{\"x\":0,\"y\":5,\"w\":6,\"h\":4}},{\"instance_id\":\"w_4\",\"widget\":\"UserContributionToplistWidget\",\"config\":{\"alias\":\"Top contributing users\"},\"position\":{\"x\":6,\"y\":5,\"w\":6,\"h\":4}},{\"instance_id\":\"w_5\",\"widget\":\"OrgsEvolutionWidget\",\"config\":{\"alias\":\"Organisation growth\"},\"position\":{\"x\":0,\"y\":9,\"w\":6,\"h\":6}},{\"instance_id\":\"w_6\",\"widget\":\"SharingGraphWidget\",\"config\":{\"alias\":\"Sharing relationships\"},\"position\":{\"x\":6,\"y\":9,\"w\":6,\"h\":6}}]', 1792347918);

INSERT IGNORE INTO `schema_migrations` (`id`, `migration_id`, `applied_at`, `duration_ms`, `status`, `error`) VALUES
(1, '20260901_082657_taxii_servers_auth_type_width', NOW(), 141, 'applied', NULL),
(2, '20260909_175232_add_id_to_keyless_tables', NOW(), 447, 'applied', NULL),
(3, '20260915_131521_tags_name_case_insensitive', NOW(), 235, 'applied', NULL),
(4, '20260915_131522_roles_perm_ai_tools', NOW(), 87, 'applied', NULL),
(5, '20260930_131926_analyst_profiles', NOW(), 121, 'applied', NULL),
(6, '20260930_131927_value_enrichment_runs', NOW(), 86, 'applied', NULL),
(7, '20260930_131928_warninglist_entries_list_value_index', NOW(), 0, 'applied', NULL),
(8, '20260930_131929_analyst_profile_selections', NOW(), 82, 'applied', NULL),
(9, '20261001_091832_allowedlist_to_warninglist', NOW(), 53, 'applied', NULL),
(10, '20261001_095359_analyst_graphs', NOW(), 143, 'applied', NULL),
(11, '20261003_092429_create_attribute_values', NOW(), 291, 'applied', NULL),
(12, '20261004_093106_create_value_ip_ranges', NOW(), 217, 'applied', NULL),
(13, '20261004_093749_attribute_value_ids', NOW(), 355, 'applied', NULL),
(14, '20261006_131940_legacy_templates_to_event_templates', NOW(), 260, 'applied', NULL),
(15, '20261006_135534_galaxies_category_sub_category', NOW(), 183, 'applied', NULL),
(16, '20261006_142036_analyst_profiles_shared', NOW(), 191, 'applied', NULL),
(17, '20261007_120823_threads_to_analyst_data', NOW(), 114, 'applied', NULL),
(18, '20261009_034014_value_keyed_correlation_counts', NOW(), 490, 'applied', NULL),
(19, '20261009_074646_value_group_correlations', NOW(), 657, 'applied', NULL),
(20, '20261009_083345_drop_shadow_attribute_correlations', NOW(), 77, 'applied', NULL),
(21, '20261010_103316_drop_attribute_value_text', NOW(), 467, 'applied', NULL),
(22, '20261013_070812_attributes_event_deleted_object', NOW(), 0, 'applied', NULL),
(23, '20261013_154619_objects_event_deleted_name', NOW(), 0, 'applied', NULL),
(24, '20261014_141955_value_address_columns', NOW(), 1297, 'applied', NULL),
(25, '20261016_180200_schema_v3_database_collation', NOW(), 36, 'applied', NULL),
(26, '20261016_180201_schema_v3_drop_tasks', NOW(), 62, 'applied', NULL),
(27, '20261016_180202_schema_v3_default_correlations', NOW(), 15, 'applied', NULL),
(28, '20261016_180203_schema_v3_no_acl_correlations', NOW(), 6, 'applied', NULL),
(29, '20261016_180204_schema_v3_over_correlating_values', NOW(), 6, 'applied', NULL),
(30, '20261016_180205_schema_v3_fuzzy_correlate_ssdeep', NOW(), 256, 'applied', NULL),
(31, '20261016_180206_schema_v3_admin_settings', NOW(), 219, 'applied', NULL),
(32, '20261016_180207_schema_v3_bruteforces', NOW(), 155, 'applied', NULL),
(33, '20261016_180208_schema_v3_news', NOW(), 155, 'applied', NULL),
(34, '20261016_180209_schema_v3_org_blocklists', NOW(), 191, 'applied', NULL),
(35, '20261016_180210_schema_v3_regexp', NOW(), 170, 'applied', NULL),
(36, '20261016_180211_schema_v3_roles', NOW(), 168, 'applied', NULL),
(37, '20261016_180212_schema_v3_scheduled_tasks', NOW(), 167, 'applied', NULL),
(38, '20261016_180213_schema_v3_threat_levels', NOW(), 221, 'applied', NULL),
(39, '20261016_180214_schema_v3_attachment_scans', NOW(), 186, 'applied', NULL),
(40, '20261016_180215_schema_v3_cake_sessions', NOW(), 204, 'applied', NULL),
(41, '20261016_180216_schema_v3_correlation_exclusions', NOW(), 186, 'applied', NULL),
(42, '20261016_180217_schema_v3_decaying_model_mappings', NOW(), 182, 'applied', NULL),
(43, '20261016_180218_schema_v3_event_report_template_variables', NOW(), 166, 'applied', NULL),
(44, '20261016_180219_schema_v3_noticelist_entries', NOW(), 180, 'applied', NULL),
(45, '20261016_180220_schema_v3_schema_migrations', NOW(), 188, 'applied', NULL),
(46, '20261016_180221_schema_v3_system_settings', NOW(), 166, 'applied', NULL),
(47, '20261016_180222_schema_v3_analyst_data_blocklists', NOW(), 178, 'applied', NULL),
(48, '20261016_180223_schema_v3_analyst_profile_selections', NOW(), 176, 'applied', NULL),
(49, '20261016_180224_schema_v3_event_delegations', NOW(), 178, 'applied', NULL),
(50, '20261016_180225_schema_v3_event_report_tags', NOW(), 192, 'applied', NULL),
(51, '20261016_180226_schema_v3_event_template_object_dependencies', NOW(), 174, 'applied', NULL),
(52, '20261016_180227_schema_v3_favourite_tags', NOW(), 177, 'applied', NULL),
(53, '20261016_180228_schema_v3_galaxy_cluster_blocklists', NOW(), 177, 'applied', NULL),
(54, '20261016_180229_schema_v3_noticelists', NOW(), 176, 'applied', NULL),
(55, '20261016_180230_schema_v3_notification_logs', NOW(), 185, 'applied', NULL),
(56, '20261016_180231_schema_v3_sharing_group_servers', NOW(), 175, 'applied', NULL),
(57, '20261016_180232_schema_v3_sighting_blocklists', NOW(), 174, 'applied', NULL),
(58, '20261016_180233_schema_v3_sightingdb_orgs', NOW(), 176, 'applied', NULL),
(59, '20261016_180234_schema_v3_tag_collection_tags', NOW(), 172, 'applied', NULL),
(60, '20261016_180235_schema_v3_value_enrichment_runs', NOW(), 178, 'applied', NULL),
(61, '20261016_180236_schema_v3_bookmarks', NOW(), 187, 'applied', NULL),
(62, '20261016_180237_schema_v3_correlation_rules', NOW(), 187, 'applied', NULL),
(63, '20261016_180238_schema_v3_event_locks', NOW(), 185, 'applied', NULL),
(64, '20261016_180239_schema_v3_rest_client_histories', NOW(), 200, 'applied', NULL),
(65, '20261016_180240_schema_v3_servers', NOW(), 194, 'applied', NULL),
(66, '20261016_180241_schema_v3_sharing_group_blueprints', NOW(), 197, 'applied', NULL),
(67, '20261016_180242_schema_v3_tag_collections', NOW(), 184, 'applied', NULL),
(68, '20261016_180243_schema_v3_taxii_servers', NOW(), 185, 'applied', NULL),
(69, '20261016_180244_schema_v3_taxonomies', NOW(), 155, 'applied', NULL),
(70, '20261016_180245_schema_v3_user_settings', NOW(), 190, 'applied', NULL),
(71, '20261016_180246_schema_v3_warninglist_types', NOW(), 161, 'applied', NULL),
(72, '20261016_180247_schema_v3_workflow_blueprints', NOW(), 187, 'applied', NULL),
(73, '20261016_180248_schema_v3_cerebrates', NOW(), 178, 'applied', NULL),
(74, '20261016_180249_schema_v3_correlations', NOW(), 56, 'applied', NULL),
(75, '20261016_180250_schema_v3_event_graph', NOW(), 199, 'applied', NULL),
(76, '20261016_180251_schema_v3_jobs', NOW(), 172, 'applied', NULL),
(77, '20261016_180252_schema_v3_object_relationships', NOW(), 173, 'applied', NULL),
(78, '20261016_180253_schema_v3_sharing_group_orgs', NOW(), 185, 'applied', NULL),
(79, '20261016_180254_schema_v3_sightingdbs', NOW(), 203, 'applied', NULL),
(80, '20261016_180255_schema_v3_user_login_profiles', NOW(), 208, 'applied', NULL),
(81, '20261016_180256_schema_v3_warninglists', NOW(), 167, 'applied', NULL),
(82, '20261016_180257_schema_v3_workflows', NOW(), 227, 'applied', NULL),
(83, '20261016_180258_schema_v3_feeds', NOW(), 294, 'applied', NULL),
(84, '20261016_180259_schema_v3_collection_elements', NOW(), 220, 'applied', NULL),
(85, '20261016_180300_schema_v3_decaying_models', NOW(), 224, 'applied', NULL),
(86, '20261016_180301_schema_v3_inbox', NOW(), 249, 'applied', NULL),
(87, '20261016_180302_schema_v3_sharing_groups', NOW(), 223, 'applied', NULL),
(88, '20261016_180303_schema_v3_dashboards', NOW(), 229, 'applied', NULL),
(89, '20261016_180304_schema_v3_users', NOW(), 205, 'applied', NULL),
(90, '20261016_180305_schema_v3_analyst_graphs', NOW(), 243, 'applied', NULL),
(91, '20261016_180306_schema_v3_analyst_profiles', NOW(), 238, 'applied', NULL),
(92, '20261016_180307_schema_v3_collections', NOW(), 242, 'applied', NULL),
(93, '20261016_180308_schema_v3_cryptographic_keys', NOW(), 213, 'applied', NULL),
(94, '20261016_180309_schema_v3_event_blocklists', NOW(), 182, 'applied', NULL),
(95, '20261016_180310_schema_v3_event_templates', NOW(), 217, 'applied', NULL),
(96, '20261016_180311_schema_v3_organisations', NOW(), 187, 'applied', NULL),
(97, '20261016_180312_schema_v3_opinions', NOW(), 253, 'applied', NULL),
(98, '20261016_180313_schema_v3_galaxies', NOW(), 202, 'applied', NULL),
(99, '20261016_180314_schema_v3_notes', NOW(), 252, 'applied', NULL),
(100, '20261016_180315_schema_v3_relationships', NOW(), 276, 'applied', NULL),
(101, '20261016_180316_schema_v3_auth_keys', NOW(), 215, 'applied', NULL),
(102, '20261016_180317_schema_v3_shadow_attributes', NOW(), 271, 'applied', NULL),
(103, '20261016_180318_schema_v3_object_templates', NOW(), 219, 'applied', NULL),
(104, '20261016_180319_schema_v3_taxonomy_predicates', NOW(), 188, 'applied', NULL),
(105, '20261016_180320_schema_v3_event_reports', NOW(), 189, 'applied', NULL),
(106, '20261016_180321_schema_v3_object_template_elements', NOW(), 186, 'applied', NULL),
(107, '20261016_180322_schema_v3_galaxy_cluster_relation_tags', NOW(), 175, 'applied', NULL),
(108, '20261016_180323_schema_v3_tags', NOW(), 199, 'applied', NULL),
(109, '20261016_180324_schema_v3_event_tags', NOW(), 177, 'applied', NULL),
(110, '20261016_180325_schema_v3_taxonomy_entries', NOW(), 176, 'applied', NULL),
(111, '20261016_180326_schema_v3_events', NOW(), 247, 'applied', NULL),
(112, '20261016_180327_schema_v3_access_logs', NOW(), 168, 'applied', NULL),
(113, '20261016_180328_schema_v3_galaxy_cluster_relations', NOW(), 222, 'applied', NULL),
(114, '20261016_180329_schema_v3_value_ip_ranges', NOW(), 6, 'applied', NULL),
(115, '20261016_180330_schema_v3_galaxy_clusters', NOW(), 300, 'applied', NULL),
(116, '20261016_180331_schema_v3_galaxy_elements', NOW(), 205, 'applied', NULL),
(117, '20261016_180332_schema_v3_attr_value_counts', NOW(), 6, 'applied', NULL),
(118, '20261016_180333_schema_v3_warninglist_entries', NOW(), 191, 'applied', NULL),
(119, '20261016_180334_schema_v3_sightings', NOW(), 222, 'applied', NULL),
(120, '20261016_180335_schema_v3_object_references', NOW(), 210, 'applied', NULL),
(121, '20261016_180336_schema_v3_objects', NOW(), 271, 'applied', NULL),
(122, '20261016_180337_schema_v3_attribute_values', NOW(), 7, 'applied', NULL),
(123, '20261016_180338_schema_v3_attribute_tags', NOW(), 187, 'applied', NULL),
(124, '20261016_180339_schema_v3_attributes', NOW(), 377, 'applied', NULL),
(125, '20261016_204637_queue_full_recorrelation', NOW(), 15, 'applied', NULL),
(126, '20261017_094559_repair_redis_serialization', NOW(), 11, 'applied', NULL),
(127, '20261018_174227_analyst_profiles_shipped_revision', NOW(), 127, 'applied', NULL);

