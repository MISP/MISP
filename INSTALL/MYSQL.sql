
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `access_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `created` datetime(4) NOT NULL,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `authkey_id` int(11) DEFAULT NULL,
  `ip` varbinary(16) DEFAULT NULL,
  `request_method` tinyint(4) NOT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `request_id` varchar(255) DEFAULT NULL,
  `controller` varchar(20) NOT NULL,
  `action` varchar(191) NOT NULL,
  `url` varchar(255) NOT NULL,
  `request` blob DEFAULT NULL,
  `response_code` smallint(6) NOT NULL,
  `memory_usage` int(11) NOT NULL,
  `duration` int(11) NOT NULL,
  `query_count` int(11) NOT NULL,
  `query_log` blob DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=60 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `admin_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `setting` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `value` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `setting` (`setting`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `allowedlist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `analyst_data_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `analyst_data_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `analyst_data_info` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `analyst_data_orgc` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `analyst_data_uuid` (`analyst_data_uuid`),
  KEY `analyst_data_orgc` (`analyst_data_orgc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `attachment_scans` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `infected` tinyint(1) NOT NULL,
  `malware_name` varchar(191) DEFAULT NULL,
  `timestamp` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index` (`type`,`attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `attribute_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  `local` tinyint(1) NOT NULL DEFAULT 0,
  `relationship_type` varchar(191) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `event_id` (`event_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `object_id` int(11) NOT NULL DEFAULT 0,
  `object_relation` varchar(255) DEFAULT NULL,
  `category` varchar(255) NOT NULL,
  `type` varchar(100) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `value1` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `value2` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT 1,
  `uuid` varchar(40) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  `first_seen` bigint(20) DEFAULT NULL,
  `last_seen` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `event_id` (`event_id`),
  KEY `object_id` (`object_id`),
  KEY `object_relation` (`object_relation`),
  KEY `value1` (`value1`(255)),
  KEY `value2` (`value2`(255)),
  KEY `type` (`type`),
  KEY `category` (`category`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `first_seen` (`first_seen`),
  KEY `last_seen` (`last_seen`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `audit_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `created` datetime NOT NULL,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `authkey_id` int(11) DEFAULT NULL,
  `ip` varbinary(16) DEFAULT NULL,
  `request_type` tinyint(4) NOT NULL,
  `request_id` varchar(255) DEFAULT NULL,
  `action` varchar(20) NOT NULL,
  `model` varchar(80) NOT NULL,
  `model_id` int(11) NOT NULL,
  `model_title` text DEFAULT NULL,
  `event_id` int(11) DEFAULT NULL,
  `change` blob DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `model_id` (`model_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_keys` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) NOT NULL,
  `authkey` varchar(72) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authkey_start` varchar(4) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authkey_end` varchar(4) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `created` int(10) unsigned NOT NULL,
  `expiration` int(10) unsigned NOT NULL,
  `read_only` tinyint(1) NOT NULL DEFAULT 0,
  `user_id` int(10) unsigned NOT NULL,
  `comment` text DEFAULT NULL,
  `allowed_ips` text DEFAULT NULL,
  `unique_ips` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `authkey_start` (`authkey_start`),
  KEY `authkey_end` (`authkey_end`),
  KEY `created` (`created`),
  KEY `expiration` (`expiration`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `bruteforces` (
  `ip` varchar(255) NOT NULL,
  `username` varchar(255) NOT NULL,
  `expire` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cake_sessions` (
  `id` varchar(255) NOT NULL DEFAULT '',
  `data` text NOT NULL,
  `expires` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cerebrates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(191) NOT NULL,
  `url` varchar(255) NOT NULL,
  `authkey` varbinary(255) NOT NULL,
  `open` tinyint(1) DEFAULT 0,
  `org_id` int(11) NOT NULL,
  `pull_orgs` tinyint(1) DEFAULT 0,
  `pull_sharing_groups` tinyint(1) DEFAULT 0,
  `self_signed` tinyint(1) DEFAULT 0,
  `cert_file` varchar(255) DEFAULT NULL,
  `client_cert_file` varchar(255) DEFAULT NULL,
  `internal` tinyint(1) NOT NULL DEFAULT 0,
  `skip_proxy` tinyint(1) NOT NULL DEFAULT 0,
  `description` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `url` (`url`),
  KEY `org_id` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `collection_elements` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `element_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `element_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `collection_id` int(10) unsigned NOT NULL,
  `description` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  UNIQUE KEY `unique_element` (`element_uuid`,`collection_id`),
  KEY `element_uuid` (`element_uuid`),
  KEY `element_type` (`element_type`),
  KEY `collection_id` (`collection_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `collections` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `org_id` int(10) unsigned NOT NULL,
  `orgc_id` int(10) unsigned NOT NULL,
  `user_id` int(10) unsigned NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned DEFAULT NULL,
  `name` varchar(191) NOT NULL,
  `type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `description` mediumtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `type` (`type`),
  KEY `org_id` (`org_id`),
  KEY `orgc_id` (`orgc_id`),
  KEY `user_id` (`user_id`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `correlation_exclusions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text NOT NULL,
  `from_json` tinyint(1) DEFAULT 0,
  `comment` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `value` (`value`(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `correlation_values` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `value` varchar(191) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `value` (`value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text NOT NULL,
  `1_event_id` int(11) NOT NULL,
  `1_attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `a_distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(11) NOT NULL,
  `a_sharing_group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `1_event_id` (`1_event_id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `1_attribute_id` (`1_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cryptographic_keys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `type` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `parent_id` int(11) NOT NULL,
  `parent_type` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `key_data` text DEFAULT NULL,
  `revoked` tinyint(1) NOT NULL DEFAULT 0,
  `fingerprint` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `type` (`type`),
  KEY `parent_id` (`parent_id`),
  KEY `parent_type` (`parent_type`),
  KEY `fingerprint` (`fingerprint`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `dashboards` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `description` text DEFAULT NULL,
  `default` tinyint(1) NOT NULL DEFAULT 0,
  `selectable` tinyint(1) NOT NULL DEFAULT 0,
  `user_id` int(11) NOT NULL DEFAULT 0,
  `restrict_to_org_id` int(11) NOT NULL DEFAULT 0,
  `restrict_to_role_id` int(11) NOT NULL DEFAULT 0,
  `restrict_to_permission_flag` varchar(191) NOT NULL DEFAULT '',
  `value` text DEFAULT NULL,
  `timestamp` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `user_id` (`user_id`),
  KEY `restrict_to_org_id` (`restrict_to_org_id`),
  KEY `restrict_to_permission_flag` (`restrict_to_permission_flag`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `decaying_model_mappings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute_type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `model_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `model_id` (`model_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `decaying_models` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `parameters` text DEFAULT NULL,
  `attribute_types` text DEFAULT NULL,
  `description` text DEFAULT NULL,
  `org_id` int(11) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `all_orgs` tinyint(1) NOT NULL DEFAULT 1,
  `ref` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `formula` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `version` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL DEFAULT '',
  `default` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `org_id` (`org_id`),
  KEY `enabled` (`enabled`),
  KEY `all_orgs` (`all_orgs`),
  KEY `version` (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `default_correlations` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `attribute_id` int(10) unsigned NOT NULL,
  `object_id` int(10) unsigned NOT NULL,
  `event_id` int(10) unsigned NOT NULL,
  `org_id` int(10) unsigned NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `object_distribution` tinyint(4) NOT NULL,
  `event_distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `object_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `event_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `1_attribute_id` int(10) unsigned NOT NULL,
  `1_object_id` int(10) unsigned NOT NULL,
  `1_event_id` int(10) unsigned NOT NULL,
  `1_org_id` int(10) unsigned NOT NULL,
  `1_distribution` tinyint(4) NOT NULL,
  `1_object_distribution` tinyint(4) NOT NULL,
  `1_event_distribution` tinyint(4) NOT NULL,
  `1_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `1_object_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `1_event_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `value_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_correlation` (`attribute_id`,`1_attribute_id`,`value_id`),
  KEY `event_id` (`event_id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `object_id` (`object_id`),
  KEY `1_event_id` (`1_event_id`),
  KEY `1_attribute_id` (`1_attribute_id`),
  KEY `1_object_id` (`1_object_id`),
  KEY `value_id` (`value_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `event_info` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `event_orgc` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `event_uuid` (`event_uuid`),
  KEY `event_orgc` (`event_orgc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_delegations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `requester_org_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `message` text DEFAULT NULL,
  `distribution` tinyint(4) NOT NULL DEFAULT -1,
  `sharing_group_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `event_id` (`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_graph` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `network_name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `network_json` mediumtext NOT NULL,
  `preview_img` mediumtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `user_id` (`user_id`),
  KEY `org_id` (`org_id`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_locks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `user_id` (`user_id`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_reports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `event_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `content` mediumtext DEFAULT NULL,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) DEFAULT NULL,
  `timestamp` int(11) NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `event_id` (`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  `local` tinyint(1) NOT NULL DEFAULT 0,
  `relationship_type` varchar(191) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `events` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `date` date NOT NULL,
  `info` text NOT NULL,
  `user_id` int(11) NOT NULL,
  `uuid` varchar(40) NOT NULL,
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
  `sighting_timestamp` int(11) NOT NULL DEFAULT 0,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  `extends_uuid` varchar(40) DEFAULT '',
  `protected` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `info` (`info`(255)),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `org_id` (`org_id`),
  KEY `orgc_id` (`orgc_id`),
  KEY `extends_uuid` (`extends_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `favourite_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tag_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `feeds` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `provider` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `url` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `rules` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) NOT NULL DEFAULT 0,
  `tag_id` int(11) NOT NULL DEFAULT 0,
  `default` tinyint(1) DEFAULT 0,
  `source_format` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT 'misp',
  `fixed_event` tinyint(1) NOT NULL DEFAULT 0,
  `delta_merge` tinyint(1) NOT NULL DEFAULT 0,
  `event_id` int(11) NOT NULL DEFAULT 0,
  `publish` tinyint(1) NOT NULL DEFAULT 0,
  `override_ids` tinyint(1) NOT NULL DEFAULT 0,
  `settings` text DEFAULT NULL,
  `input_source` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL DEFAULT 'network',
  `delete_local_file` tinyint(1) DEFAULT 0,
  `lookup_visible` tinyint(1) DEFAULT 0,
  `headers` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `caching_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `force_to_ids` tinyint(1) NOT NULL DEFAULT 0,
  `orgc_id` int(11) NOT NULL DEFAULT 0,
  `tag_collection_id` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `input_source` (`input_source`),
  KEY `orgc_id` (`orgc_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `fuzzy_correlate_ssdeep` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `chunk` varchar(12) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `chunk` (`chunk`),
  KEY `attribute_id` (`attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `galaxies` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL DEFAULT '',
  `type` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `version` varchar(255) NOT NULL,
  `icon` varchar(255) NOT NULL DEFAULT '',
  `namespace` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'misp',
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `local_only` tinyint(1) NOT NULL DEFAULT 0,
  `kill_chain_order` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `type` (`type`),
  KEY `namespace` (`namespace`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `galaxy_cluster_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cluster_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `cluster_info` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `cluster_orgc` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `cluster_uuid` (`cluster_uuid`),
  KEY `cluster_orgc` (`cluster_orgc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `galaxy_cluster_relation_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `galaxy_cluster_relation_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `galaxy_cluster_relation_id` (`galaxy_cluster_relation_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `galaxy_cluster_relations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `galaxy_cluster_id` int(11) NOT NULL,
  `referenced_galaxy_cluster_id` int(11) NOT NULL,
  `referenced_galaxy_cluster_uuid` varchar(255) NOT NULL,
  `referenced_galaxy_cluster_type` text NOT NULL,
  `galaxy_cluster_uuid` varchar(40) NOT NULL,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) DEFAULT NULL,
  `default` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `galaxy_cluster_id` (`galaxy_cluster_id`),
  KEY `referenced_galaxy_cluster_id` (`referenced_galaxy_cluster_id`),
  KEY `referenced_galaxy_cluster_type` (`referenced_galaxy_cluster_type`(255)),
  KEY `galaxy_cluster_uuid` (`galaxy_cluster_uuid`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `default` (`default`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `galaxy_clusters` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) NOT NULL DEFAULT '',
  `collection_uuid` varchar(255) NOT NULL,
  `type` varchar(255) NOT NULL,
  `value` text NOT NULL,
  `tag_name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` text NOT NULL,
  `galaxy_id` int(11) NOT NULL,
  `source` varchar(255) NOT NULL DEFAULT '',
  `authors` text NOT NULL,
  `version` int(11) DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) DEFAULT NULL,
  `org_id` int(11) NOT NULL,
  `orgc_id` int(11) NOT NULL,
  `default` tinyint(1) NOT NULL DEFAULT 0,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `extends_uuid` varchar(40) DEFAULT '',
  `extends_version` int(11) DEFAULT 0,
  `published` tinyint(1) NOT NULL DEFAULT 0,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `value` (`value`(255)),
  KEY `uuid` (`uuid`),
  KEY `collection_uuid` (`collection_uuid`),
  KEY `galaxy_id` (`galaxy_id`),
  KEY `version` (`version`),
  KEY `tag_name` (`tag_name`),
  KEY `type` (`type`),
  KEY `org_id` (`org_id`),
  KEY `orgc_id` (`orgc_id`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `extends_uuid` (`extends_uuid`),
  KEY `extends_version` (`extends_version`),
  KEY `default` (`default`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `galaxy_elements` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `galaxy_cluster_id` int(11) NOT NULL,
  `key` varchar(255) NOT NULL DEFAULT '',
  `value` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `key` (`key`),
  KEY `value` (`value`(255)),
  KEY `galaxy_cluster_id` (`galaxy_cluster_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `inbox` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `title` varchar(191) NOT NULL,
  `type` varchar(191) NOT NULL,
  `ip` varchar(191) NOT NULL,
  `user_agent` text DEFAULT NULL,
  `user_agent_sha256` varchar(64) NOT NULL,
  `comment` text DEFAULT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `timestamp` int(11) NOT NULL,
  `store_as_file` tinyint(1) NOT NULL DEFAULT 0,
  `data` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `title` (`title`),
  KEY `type` (`type`),
  KEY `user_agent_sha256` (`user_agent_sha256`),
  KEY `ip` (`ip`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `jobs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `worker` varchar(32) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `job_type` varchar(32) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `job_input` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `status` tinyint(4) NOT NULL DEFAULT 0,
  `retries` int(11) NOT NULL DEFAULT 0,
  `message` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `progress` int(11) NOT NULL DEFAULT 0,
  `org_id` int(11) NOT NULL DEFAULT 0,
  `process_id` varchar(36) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` text DEFAULT NULL,
  `created` datetime NOT NULL,
  `model` varchar(80) NOT NULL,
  `model_id` int(11) NOT NULL,
  `action` varchar(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  `change` text DEFAULT NULL,
  `email` varchar(255) NOT NULL DEFAULT '',
  `org` varchar(255) NOT NULL DEFAULT '',
  `description` text DEFAULT NULL,
  `ip` varchar(45) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=654 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `news` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `title` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `user_id` int(11) NOT NULL,
  `date_created` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `no_acl_correlations` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `attribute_id` int(10) unsigned NOT NULL,
  `1_attribute_id` int(10) unsigned NOT NULL,
  `event_id` int(10) unsigned NOT NULL,
  `1_event_id` int(10) unsigned NOT NULL,
  `value_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_correlation` (`attribute_id`,`1_attribute_id`,`value_id`),
  KEY `event_id` (`event_id`),
  KEY `1_event_id` (`1_event_id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `1_attribute_id` (`1_attribute_id`),
  KEY `value_id` (`value_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `notes` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authors` text DEFAULT NULL,
  `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned DEFAULT NULL,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `note` mediumtext DEFAULT NULL,
  `language` varchar(16) DEFAULT 'en',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `object_uuid` (`object_uuid`),
  KEY `object_type` (`object_type`),
  KEY `org_uuid` (`org_uuid`),
  KEY `orgc_uuid` (`orgc_uuid`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `noticelist_entries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `noticelist_id` int(11) NOT NULL,
  `data` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `noticelist_id` (`noticelist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `noticelists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `expanded_name` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `ref` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `geographical_area` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `version` int(11) NOT NULL DEFAULT 1,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  KEY `geographical_area` (`geographical_area`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `notification_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `type` varchar(255) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `object_references` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `object_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `source_uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `referenced_uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `referenced_id` int(11) NOT NULL,
  `referenced_type` int(11) NOT NULL DEFAULT 0,
  `relationship_type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `object_id` (`object_id`),
  KEY `referenced_id` (`referenced_id`),
  KEY `event_id` (`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `object_relationships` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `version` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `format` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `object_template_elements` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `object_template_id` int(11) NOT NULL,
  `object_relation` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `ui-priority` int(11) NOT NULL,
  `categories` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `sane_default` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `values_list` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `disable_correlation` tinyint(1) DEFAULT NULL,
  `multiple` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `object_relation` (`object_relation`),
  KEY `type` (`type`),
  KEY `object_template_id` (`object_template_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `object_templates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `meta-category` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `version` int(11) NOT NULL,
  `requirements` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `fixed` tinyint(1) NOT NULL DEFAULT 0,
  `active` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `org_id` (`org_id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `meta-category` (`meta-category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `objects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `meta-category` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `template_uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `template_version` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) DEFAULT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `first_seen` bigint(20) DEFAULT NULL,
  `last_seen` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `template_uuid` (`template_uuid`),
  KEY `template_version` (`template_version`),
  KEY `meta-category` (`meta-category`),
  KEY `event_id` (`event_id`),
  KEY `timestamp` (`timestamp`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `first_seen` (`first_seen`),
  KEY `last_seen` (`last_seen`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `opinions` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authors` text DEFAULT NULL,
  `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned DEFAULT NULL,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `opinion` int(10) unsigned DEFAULT NULL,
  `comment` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `object_uuid` (`object_uuid`),
  KEY `object_type` (`object_type`),
  KEY `org_uuid` (`org_uuid`),
  KEY `orgc_uuid` (`orgc_uuid`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `opinion` (`opinion`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `org_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `org_name` varchar(255) NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `org_uuid` (`org_uuid`),
  KEY `org_name` (`org_name`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `organisations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL DEFAULT '',
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `description` text DEFAULT NULL,
  `type` varchar(255) NOT NULL DEFAULT '',
  `nationality` varchar(255) NOT NULL DEFAULT '',
  `sector` varchar(255) NOT NULL DEFAULT '',
  `created_by` int(11) NOT NULL DEFAULT 0,
  `uuid` varchar(40) DEFAULT NULL,
  `contacts` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `local` tinyint(1) NOT NULL DEFAULT 0,
  `restricted_to_domain` text DEFAULT NULL,
  `landingpage` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  UNIQUE KEY `uuid` (`uuid`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `over_correlating_values` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `value` varchar(191) NOT NULL,
  `occurrence` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `value` (`value`),
  KEY `occurrence` (`occurrence`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `posts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `user_id` int(11) NOT NULL,
  `contents` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `post_id` int(11) NOT NULL DEFAULT 0,
  `thread_id` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `post_id` (`post_id`),
  KEY `thread_id` (`thread_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `regexp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `regexp` varchar(255) NOT NULL,
  `replacement` varchar(255) NOT NULL,
  `type` varchar(100) NOT NULL DEFAULT 'ALL',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `relationships` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authors` text DEFAULT NULL,
  `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned DEFAULT NULL,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `relationship_type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `related_object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `related_object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `object_uuid` (`object_uuid`),
  KEY `object_type` (`object_type`),
  KEY `org_uuid` (`org_uuid`),
  KEY `orgc_uuid` (`orgc_uuid`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `relationship_type` (`relationship_type`),
  KEY `related_object_uuid` (`related_object_uuid`),
  KEY `related_object_type` (`related_object_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `rest_client_histories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `headers` text DEFAULT NULL,
  `body` text DEFAULT NULL,
  `url` text DEFAULT NULL,
  `http_method` varchar(255) DEFAULT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `use_full_path` tinyint(1) DEFAULT 0,
  `show_result` tinyint(1) DEFAULT 0,
  `skip_ssl` tinyint(1) DEFAULT 0,
  `outcome` int(11) NOT NULL,
  `bookmark` tinyint(1) NOT NULL DEFAULT 0,
  `bookmark_name` varchar(255) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `user_id` (`user_id`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `roles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
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
  `memory_limit` varchar(255) DEFAULT '',
  `max_execution_time` varchar(255) DEFAULT '',
  `restricted_to_site_admin` tinyint(1) NOT NULL DEFAULT 0,
  `perm_publish_zmq` tinyint(1) NOT NULL DEFAULT 0,
  `perm_publish_kafka` tinyint(1) NOT NULL DEFAULT 0,
  `perm_decaying` tinyint(1) NOT NULL DEFAULT 0,
  `enforce_rate_limit` tinyint(1) NOT NULL DEFAULT 0,
  `rate_limit_count` int(11) NOT NULL DEFAULT 0,
  `perm_galaxy_editor` tinyint(1) NOT NULL DEFAULT 0,
  `perm_warninglist` tinyint(1) NOT NULL DEFAULT 0,
  `perm_view_feed_correlations` tinyint(1) NOT NULL DEFAULT 0,
  `perm_analyst_data` tinyint(1) NOT NULL DEFAULT 0,
  `perm_skip_otp` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `url` varchar(255) NOT NULL,
  `authkey` varbinary(255) NOT NULL,
  `org_id` int(11) NOT NULL,
  `push` tinyint(1) NOT NULL,
  `pull` tinyint(1) NOT NULL,
  `push_sightings` tinyint(1) NOT NULL DEFAULT 0,
  `push_galaxy_clusters` tinyint(1) NOT NULL DEFAULT 0,
  `push_analyst_data` tinyint(1) NOT NULL DEFAULT 0,
  `pull_analyst_data` tinyint(1) NOT NULL DEFAULT 0,
  `pull_galaxy_clusters` tinyint(1) NOT NULL DEFAULT 0,
  `lastpulledid` int(11) DEFAULT NULL,
  `lastpushedid` int(11) DEFAULT NULL,
  `organization` varchar(10) DEFAULT NULL,
  `remote_org_id` int(11) NOT NULL,
  `publish_without_email` tinyint(1) NOT NULL DEFAULT 0,
  `unpublish_event` tinyint(1) NOT NULL DEFAULT 0,
  `self_signed` tinyint(1) NOT NULL,
  `pull_rules` text NOT NULL,
  `push_rules` text NOT NULL,
  `cert_file` varchar(255) DEFAULT NULL,
  `client_cert_file` varchar(255) DEFAULT NULL,
  `internal` tinyint(1) NOT NULL DEFAULT 0,
  `skip_proxy` tinyint(1) NOT NULL DEFAULT 0,
  `remove_missing_tags` tinyint(1) NOT NULL DEFAULT 0,
  `caching_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `priority` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `priority` (`priority`),
  KEY `remote_org_id` (`remote_org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `shadow_attribute_correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `value` text NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `a_distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(11) DEFAULT NULL,
  `a_sharing_group_id` int(11) DEFAULT NULL,
  `attribute_id` int(11) NOT NULL,
  `1_shadow_attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `1_event_id` int(11) NOT NULL,
  `info` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `a_sharing_group_id` (`a_sharing_group_id`),
  KEY `event_id` (`event_id`),
  KEY `1_event_id` (`1_event_id`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `1_shadow_attribute_id` (`1_shadow_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `shadow_attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `old_id` int(11) DEFAULT 0,
  `event_id` int(11) NOT NULL,
  `type` varchar(100) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `category` varchar(255) NOT NULL,
  `value1` text DEFAULT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT 1,
  `uuid` varchar(40) NOT NULL,
  `value2` text DEFAULT NULL,
  `org_id` int(11) NOT NULL,
  `email` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `event_org_id` int(11) NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `event_uuid` varchar(40) NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `proposal_to_delete` tinyint(1) NOT NULL DEFAULT 0,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  `first_seen` bigint(20) DEFAULT NULL,
  `last_seen` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `event_uuid` (`event_uuid`),
  KEY `event_org_id` (`event_org_id`),
  KEY `uuid` (`uuid`),
  KEY `old_id` (`old_id`),
  KEY `value1` (`value1`(255)),
  KEY `value2` (`value2`(255)),
  KEY `type` (`type`),
  KEY `category` (`category`),
  KEY `first_seen` (`first_seen`),
  KEY `last_seen` (`last_seen`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sharing_group_blueprints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `sharing_group_id` int(11) DEFAULT NULL,
  `rules` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `org_id` (`org_id`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sharing_group_orgs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sharing_group_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `extend` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sharing_group_servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sharing_group_id` int(11) NOT NULL,
  `server_id` int(11) NOT NULL,
  `all_orgs` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `server_id` (`server_id`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sharing_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `releasability` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `uuid` varchar(40) NOT NULL,
  `organisation_uuid` varchar(40) NOT NULL,
  `org_id` int(11) NOT NULL,
  `sync_user_id` int(11) NOT NULL DEFAULT 0,
  `active` tinyint(1) NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `local` tinyint(1) NOT NULL,
  `roaming` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  UNIQUE KEY `name` (`name`),
  KEY `org_id` (`org_id`),
  KEY `sync_user_id` (`sync_user_id`),
  KEY `organisation_uuid` (`organisation_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sighting_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `org_name` varchar(255) NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `org_uuid` (`org_uuid`),
  KEY `org_name` (`org_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sightingdb_orgs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sightingdb_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `sightingdb_id` (`sightingdb_id`),
  KEY `org_id` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sightingdbs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `owner` varchar(255) DEFAULT '',
  `host` varchar(255) DEFAULT 'http://localhost',
  `port` int(11) DEFAULT 9999,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `skip_proxy` tinyint(1) NOT NULL DEFAULT 0,
  `ssl_skip_verification` tinyint(1) NOT NULL DEFAULT 0,
  `namespace` varchar(255) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  KEY `owner` (`owner`),
  KEY `host` (`host`),
  KEY `port` (`port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sightings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `date_sighting` bigint(20) NOT NULL,
  `uuid` varchar(255) DEFAULT '',
  `source` varchar(255) DEFAULT '',
  `type` int(11) DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `attribute_id` (`attribute_id`),
  KEY `event_id` (`event_id`),
  KEY `org_id` (`org_id`),
  KEY `source` (`source`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `system_settings` (
  `setting` varchar(255) NOT NULL,
  `value` blob NOT NULL,
  PRIMARY KEY (`setting`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tag_collection_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tag_collection_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tag_collection_id` (`tag_collection_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tag_collections` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `all_orgs` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `user_id` (`user_id`),
  KEY `org_id` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `colour` varchar(7) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `exportable` tinyint(1) NOT NULL,
  `org_id` int(11) NOT NULL DEFAULT 0,
  `user_id` int(11) NOT NULL DEFAULT 0,
  `hide_tag` tinyint(1) NOT NULL DEFAULT 0,
  `numerical_value` int(11) DEFAULT NULL,
  `is_galaxy` tinyint(1) NOT NULL DEFAULT 0,
  `is_custom_galaxy` tinyint(1) NOT NULL DEFAULT 0,
  `local_only` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  KEY `org_id` (`org_id`),
  KEY `user_id` (`user_id`),
  KEY `numerical_value` (`numerical_value`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tasks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(100) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `timer` int(11) NOT NULL,
  `scheduled_time` varchar(8) NOT NULL DEFAULT '6:00',
  `process_id` varchar(32) DEFAULT NULL,
  `description` varchar(255) NOT NULL,
  `next_execution_time` int(11) NOT NULL,
  `message` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `taxii_servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `owner` varchar(191) NOT NULL,
  `baseurl` varchar(191) NOT NULL,
  `api_root` varchar(191) NOT NULL DEFAULT '0',
  `description` text DEFAULT NULL,
  `filters` text DEFAULT NULL,
  `api_key` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `collection` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `baseurl` (`baseurl`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `taxonomies` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `namespace` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `version` int(11) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `exclusive` tinyint(1) DEFAULT 0,
  `required` tinyint(1) NOT NULL DEFAULT 0,
  `highlighted` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `taxonomy_entries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `taxonomy_predicate_id` int(11) NOT NULL,
  `value` text NOT NULL,
  `expanded` text DEFAULT NULL,
  `colour` varchar(7) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `numerical_value` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `taxonomy_predicate_id` (`taxonomy_predicate_id`),
  KEY `numerical_value` (`numerical_value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `taxonomy_predicates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `taxonomy_id` int(11) NOT NULL,
  `value` text NOT NULL,
  `expanded` text DEFAULT NULL,
  `colour` varchar(7) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `exclusive` tinyint(1) DEFAULT 0,
  `numerical_value` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `taxonomy_id` (`taxonomy_id`),
  KEY `numerical_value` (`numerical_value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `template_element_attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_element_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT 1,
  `category` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `complex` tinyint(1) NOT NULL,
  `type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `mandatory` tinyint(1) NOT NULL,
  `batch` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `template_element_files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_element_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `category` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `malware` tinyint(1) NOT NULL,
  `mandatory` tinyint(1) NOT NULL,
  `batch` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `template_element_texts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `template_element_id` int(11) NOT NULL,
  `text` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `template_elements` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_id` int(11) NOT NULL,
  `position` int(11) NOT NULL,
  `element_definition` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=48 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `template_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `templates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `description` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `org` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `share` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `threads` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `user_id` int(11) NOT NULL,
  `post_count` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `title` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `org_id` int(11) NOT NULL,
  `sharing_group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `event_id` (`event_id`),
  KEY `org_id` (`org_id`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `threat_levels` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `form_description` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_login_profiles` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `user_id` int(11) NOT NULL,
  `status` varchar(191) DEFAULT NULL,
  `ip` varchar(191) DEFAULT NULL,
  `user_agent` varchar(191) DEFAULT NULL,
  `accept_lang` varchar(191) DEFAULT NULL,
  `geoip` varchar(191) DEFAULT NULL,
  `ua_platform` varchar(191) DEFAULT NULL,
  `ua_browser` varchar(191) DEFAULT NULL,
  `ua_pattern` varchar(191) DEFAULT NULL,
  `hash` varchar(32) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `hash` (`hash`),
  KEY `ip` (`ip`),
  KEY `status` (`status`),
  KEY `geoip` (`geoip`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `setting` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `value` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `user_id` int(11) NOT NULL,
  `timestamp` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_setting` (`user_id`,`setting`),
  KEY `setting` (`setting`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(255) NOT NULL,
  `org_id` int(11) NOT NULL,
  `server_id` int(11) NOT NULL DEFAULT 0,
  `email` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `autoalert` tinyint(1) NOT NULL DEFAULT 0,
  `authkey` varchar(40) DEFAULT NULL,
  `invited_by` int(11) NOT NULL DEFAULT 0,
  `gpgkey` longtext DEFAULT NULL,
  `certif_public` longtext DEFAULT NULL,
  `nids_sid` int(15) NOT NULL DEFAULT 0,
  `termsaccepted` tinyint(1) NOT NULL DEFAULT 0,
  `newsread` int(11) unsigned DEFAULT 0,
  `role_id` int(11) NOT NULL DEFAULT 0,
  `change_pw` tinyint(1) NOT NULL DEFAULT 0,
  `contactalert` tinyint(1) NOT NULL DEFAULT 0,
  `disabled` tinyint(1) NOT NULL DEFAULT 0,
  `expiration` datetime DEFAULT NULL,
  `current_login` int(11) DEFAULT 0,
  `last_login` int(11) DEFAULT 0,
  `force_logout` tinyint(1) NOT NULL DEFAULT 0,
  `date_created` bigint(20) DEFAULT NULL,
  `date_modified` bigint(20) DEFAULT NULL,
  `sub` varchar(255) DEFAULT NULL,
  `external_auth_required` tinyint(1) NOT NULL DEFAULT 0,
  `external_auth_key` text DEFAULT NULL,
  `last_api_access` int(11) DEFAULT 0,
  `notification_daily` tinyint(1) NOT NULL DEFAULT 0,
  `notification_weekly` tinyint(1) NOT NULL DEFAULT 0,
  `notification_monthly` tinyint(1) NOT NULL DEFAULT 0,
  `totp` varchar(255) DEFAULT NULL,
  `hotp_counter` int(11) DEFAULT NULL,
  `last_pw_change` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `sub` (`sub`),
  KEY `org_id` (`org_id`),
  KEY `server_id` (`server_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `warninglist_entries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `warninglist_id` int(11) NOT NULL,
  `comment` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `warninglist_id` (`warninglist_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `warninglist_types` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `warninglist_id` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `warninglists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL DEFAULT 'string',
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `version` int(11) NOT NULL DEFAULT 1,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `default` tinyint(1) NOT NULL DEFAULT 1,
  `category` varchar(20) NOT NULL DEFAULT 'false_positive',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `workflow_blueprints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `description` varchar(191) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `default` tinyint(1) NOT NULL DEFAULT 0,
  `data` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `workflows` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `description` varchar(191) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `counter` int(11) NOT NULL DEFAULT 0,
  `trigger_id` varchar(191) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `debug_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `data` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `timestamp` (`timestamp`),
  KEY `trigger_id` (`trigger_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;



-- --------------------------------------------------------

--
-- Default values for initial installation
--

INSERT IGNORE INTO `admin_settings` (`id`, `setting`, `value`) VALUES
(1, 'db_version', '126');

INSERT IGNORE INTO `feeds` (`id`, `provider`, `name`, `url`, `distribution`, `default`, `enabled`) VALUES
(1, 'CIRCL', 'CIRCL OSINT Feed', 'https://www.circl.lu/doc/misp/feed-osint', 3, 1, 0),
(2, 'Botvrij.eu', 'The Botvrij.eu Data', 'https://www.botvrij.eu/data/feed-osint', 3, 1, 0);

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

INSERT IGNORE INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_publish_kafka`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `perm_decaying`, `default_role`, `memory_limit`, `max_execution_time`, `restricted_to_site_admin`, `enforce_rate_limit`, `rate_limit_count`, `perm_galaxy_editor`, `perm_warninglist`, `perm_view_feed_correlations`, `perm_analyst_data`, `perm_skip_otp`)
VALUES (1, 'admin', NOW(), NOW(),        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, NULL, NULL, 0, 0, 0, 1, 1, 1, 1, 0);

INSERT IGNORE INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_publish_kafka`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `perm_decaying`, `default_role`, `memory_limit`, `max_execution_time`, `restricted_to_site_admin`, `enforce_rate_limit`, `rate_limit_count`, `perm_galaxy_editor`, `perm_warninglist`, `perm_view_feed_correlations`, `perm_analyst_data`, `perm_skip_otp`)
VALUES (2, 'Org Admin', NOW(), NOW(),    1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, NULL, NULL, 0, 0, 0, 0, 0, 0, 1, 0);

INSERT IGNORE INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_publish_kafka`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `perm_decaying`, `default_role`, `memory_limit`, `max_execution_time`, `restricted_to_site_admin`, `enforce_rate_limit`, `rate_limit_count`, `perm_galaxy_editor`, `perm_warninglist`, `perm_view_feed_correlations`, `perm_analyst_data`, `perm_skip_otp`)
VALUES (3, 'User', NOW(), NOW(),         1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, NULL, NULL, 0, 0, 0, 0, 0, 0, 1, 0);

INSERT IGNORE INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_publish_kafka`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `perm_decaying`, `default_role`, `memory_limit`, `max_execution_time`, `restricted_to_site_admin`, `enforce_rate_limit`, `rate_limit_count`, `perm_galaxy_editor`, `perm_warninglist`, `perm_view_feed_correlations`, `perm_analyst_data`, `perm_skip_otp`)
VALUES (4, 'Publisher', NOW(), NOW(),    1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, NULL, NULL, 0, 0, 0, 0, 0, 0, 1, 0);

INSERT IGNORE INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_publish_kafka`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `perm_decaying`, `default_role`, `memory_limit`, `max_execution_time`, `restricted_to_site_admin`, `enforce_rate_limit`, `rate_limit_count`, `perm_galaxy_editor`, `perm_warninglist`, `perm_view_feed_correlations`, `perm_analyst_data`, `perm_skip_otp`)
VALUES (5, 'Sync user', NOW(), NOW(),    1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, NULL, NULL, 0, 0, 0, 0, 0, 0, 1, 0);

INSERT IGNORE INTO `roles` (`id`, `name`, `created`, `modified`, `perm_add`, `perm_modify`, `perm_modify_org`, `perm_publish`, `perm_publish_zmq`, `perm_publish_kafka`, `perm_sync`, `perm_admin`, `perm_audit`, `perm_full`, `perm_auth`, `perm_regexp_access`, `perm_tagger`, `perm_site_admin`, `perm_template`, `perm_sharing_group`, `perm_tag_editor`, `perm_delegate`, `perm_sighting`, `perm_object_template`, `perm_decaying`, `default_role`, `memory_limit`, `max_execution_time`, `restricted_to_site_admin`, `enforce_rate_limit`, `rate_limit_count`, `perm_galaxy_editor`, `perm_warninglist`, `perm_view_feed_correlations`, `perm_analyst_data`, `perm_skip_otp`)
VALUES (6, 'Read Only', NOW(), NOW(),    0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0);

-- --------------------------------------------------------

--
-- Initial threat levels
--

INSERT IGNORE INTO `threat_levels` (`id`, `name`, `description`, `form_description`)
VALUES
  (1, 'High', '*high* means sophisticated APT malware or 0-day attack', 'Sophisticated APT malware or 0-day attack'),
  (2, 'Medium', '*medium* means APT malware', 'APT malware'),
  (3, 'Low', '*low* means mass-malware', 'Mass-malware'),
  (4, 'Undefined', '*undefined* no risk', 'No risk');

-- --------------------------------------------------------

--
-- Default templates
--

INSERT IGNORE INTO `templates` (`id`, `name`, `description`, `org`, `share`) VALUES
(1, 'Phishing E-mail', 'Create a MISP event about a Phishing E-mail.', 'MISP', 1),
(2, 'Phishing E-mail with malicious attachment', 'A MISP event based on Spear-phishing containing a malicious attachment. This event can include anything from the description of the e-mail itself, the malicious attachment and its description as well as the results of the analysis done on the malicious f', 'MISP', 1),
(3, 'Malware Report', 'This is a template for a generic malware report. ', 'MISP', 1),
(4, 'Indicator List', 'A simple template for indicator lists.', 'MISP', 1);

INSERT IGNORE INTO `template_elements` (`id`, `template_id`, `position`, `element_definition`) VALUES
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

INSERT IGNORE INTO `template_element_attributes` (`id`, `template_element_id`, `name`, `description`, `to_ids`, `category`, `complex`, `type`, `mandatory`, `batch`) VALUES
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

INSERT IGNORE INTO `template_element_files` (`id`, `template_element_id`, `name`, `description`, `category`, `malware`, `mandatory`, `batch`) VALUES
(1, 14, 'Malicious Attachment', 'The file (or files) that was (were) attached to the e-mail itself.', 'Payload delivery', 1, 0, 1),
(2, 21, 'Payload installation', 'Payload installation detected during the analysis', 'Payload installation', 1, 0, 1),
(3, 30, 'Malware sample', 'The sample that the report is based on', 'Payload delivery', 1, 0, 0),
(4, 40, 'Artifacts dropped (Sample)', 'Upload any files that were dropped during the analysis.', 'Artifacts dropped', 1, 0, 1);

INSERT IGNORE INTO `template_element_texts` (`id`, `name`, `template_element_id`, `text`) VALUES
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

INSERT IGNORE INTO `org_blocklists` (`org_uuid`, `created`, `org_name`, `comment`) VALUES
('58d38339-7b24-4386-b4b4-4c0f950d210f', NOW(), 'Setec Astrononomy', 'default example'),
('58d38326-eda8-443a-9fa8-4e12950d210f', NOW(), 'Acme Finance', 'default example');

INSERT IGNORE INTO `admin_settings` (`setting`, `value`) VALUES 
('fix_login', NOW()),
('default_role', 3);
