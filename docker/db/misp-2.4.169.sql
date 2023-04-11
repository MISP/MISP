-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)
--
-- Host: 127.0.0.1    Database: misp
-- ------------------------------------------------------
-- Server version	8.0.19
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO,ANSI' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table "access_logs"
--

DROP TABLE IF EXISTS "access_logs";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "access_logs" (
  "id" int NOT NULL AUTO_INCREMENT,
  "created" datetime(4) NOT NULL,
  "user_id" int NOT NULL,
  "org_id" int NOT NULL,
  "authkey_id" int DEFAULT NULL,
  "ip" varbinary(16) DEFAULT NULL,
  "request_method" tinyint NOT NULL,
  "user_agent" varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  "request_id" varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  "controller" varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  "action" varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  "url" varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  "request" blob,
  "response_code" smallint NOT NULL,
  "memory_usage" int NOT NULL,
  "duration" int NOT NULL,
  "query_count" int NOT NULL,
  "query_log" blob,
  PRIMARY KEY ("id"),
  KEY "user_id" ("user_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "access_logs"
--

LOCK TABLES "access_logs" WRITE;
/*!40000 ALTER TABLE "access_logs" DISABLE KEYS */;
/*!40000 ALTER TABLE "access_logs" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "admin_settings"
--

DROP TABLE IF EXISTS "admin_settings";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "admin_settings" (
  "id" int NOT NULL AUTO_INCREMENT,
  "setting" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "value" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "setting" ("setting")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "admin_settings"
--

LOCK TABLES "admin_settings" WRITE;
/*!40000 ALTER TABLE "admin_settings" DISABLE KEYS */;
INSERT INTO "admin_settings" VALUES (1,'db_version','106');
/*!40000 ALTER TABLE "admin_settings" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "allowedlist"
--

DROP TABLE IF EXISTS "allowedlist";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "allowedlist" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "allowedlist"
--

LOCK TABLES "allowedlist" WRITE;
/*!40000 ALTER TABLE "allowedlist" DISABLE KEYS */;
/*!40000 ALTER TABLE "allowedlist" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "attachment_scans"
--

DROP TABLE IF EXISTS "attachment_scans";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "attachment_scans" (
  "id" int NOT NULL AUTO_INCREMENT,
  "type" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "attribute_id" int NOT NULL,
  "infected" tinyint(1) NOT NULL,
  "malware_name" varchar(191) DEFAULT NULL,
  "timestamp" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "index" ("type","attribute_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "attachment_scans"
--

LOCK TABLES "attachment_scans" WRITE;
/*!40000 ALTER TABLE "attachment_scans" DISABLE KEYS */;
/*!40000 ALTER TABLE "attachment_scans" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "attribute_tags"
--

DROP TABLE IF EXISTS "attribute_tags";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "attribute_tags" (
  "id" int NOT NULL AUTO_INCREMENT,
  "attribute_id" int NOT NULL,
  "event_id" int NOT NULL,
  "tag_id" int NOT NULL,
  "local" tinyint(1) NOT NULL DEFAULT '0',
  "relationship_type" varchar(191) DEFAULT '',
  PRIMARY KEY ("id"),
  KEY "attribute_id" ("attribute_id"),
  KEY "event_id" ("event_id"),
  KEY "tag_id" ("tag_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "attribute_tags"
--

LOCK TABLES "attribute_tags" WRITE;
/*!40000 ALTER TABLE "attribute_tags" DISABLE KEYS */;
/*!40000 ALTER TABLE "attribute_tags" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "attributes"
--

DROP TABLE IF EXISTS "attributes";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "attributes" (
  "id" int NOT NULL AUTO_INCREMENT,
  "event_id" int NOT NULL,
  "object_id" int NOT NULL DEFAULT '0',
  "object_relation" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "category" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "type" varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "value1" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "value2" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "to_ids" tinyint(1) NOT NULL DEFAULT '1',
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "distribution" tinyint NOT NULL DEFAULT '0',
  "sharing_group_id" int NOT NULL,
  "comment" text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  "deleted" tinyint(1) NOT NULL DEFAULT '0',
  "disable_correlation" tinyint(1) NOT NULL DEFAULT '0',
  "first_seen" bigint DEFAULT NULL,
  "last_seen" bigint DEFAULT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  KEY "event_id" ("event_id"),
  KEY "object_id" ("object_id"),
  KEY "object_relation" ("object_relation"),
  KEY "value1" ("value1"(255)),
  KEY "value2" ("value2"(255)),
  KEY "type" ("type"),
  KEY "category" ("category"),
  KEY "sharing_group_id" ("sharing_group_id"),
  KEY "first_seen" ("first_seen"),
  KEY "last_seen" ("last_seen"),
  KEY "timestamp" ("timestamp")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "attributes"
--

LOCK TABLES "attributes" WRITE;
/*!40000 ALTER TABLE "attributes" DISABLE KEYS */;
/*!40000 ALTER TABLE "attributes" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "audit_logs"
--

DROP TABLE IF EXISTS "audit_logs";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "audit_logs" (
  "id" int NOT NULL AUTO_INCREMENT,
  "created" datetime NOT NULL,
  "user_id" int NOT NULL,
  "org_id" int NOT NULL,
  "authkey_id" int DEFAULT NULL,
  "ip" varbinary(16) DEFAULT NULL,
  "request_type" tinyint NOT NULL,
  "request_id" varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  "request_action" varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  "model" varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  "model_id" int NOT NULL,
  "model_title" text COLLATE utf8mb4_unicode_ci,
  "event_id" int DEFAULT NULL,
  "change" blob,
  PRIMARY KEY ("id"),
  KEY "event_id" ("event_id"),
  KEY "model_id" ("model_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "audit_logs"
--

LOCK TABLES "audit_logs" WRITE;
/*!40000 ALTER TABLE "audit_logs" DISABLE KEYS */;
/*!40000 ALTER TABLE "audit_logs" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "auth_keys"
--

DROP TABLE IF EXISTS "auth_keys";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "auth_keys" (
  "id" int unsigned NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  "authkey" varchar(72) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  "authkey_start" varchar(4) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  "authkey_end" varchar(4) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  "created" int unsigned NOT NULL,
  "expiration" int unsigned NOT NULL,
  "read_only" tinyint(1) NOT NULL DEFAULT '0',
  "user_id" int unsigned NOT NULL,
  "comment" text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  "allowed_ips" text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY ("id"),
  KEY "authkey_start" ("authkey_start"),
  KEY "authkey_end" ("authkey_end"),
  KEY "created" ("created"),
  KEY "expiration" ("expiration"),
  KEY "user_id" ("user_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table "bruteforces"
--

DROP TABLE IF EXISTS "bruteforces";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "bruteforces" (
  "ip" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "username" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "expire" datetime NOT NULL
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table "cake_sessions"
--

DROP TABLE IF EXISTS "cake_sessions";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "cake_sessions" (
  "id" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  "data" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "expires" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "expires" ("expires")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "cake_sessions"
--

LOCK TABLES "cake_sessions" WRITE;
/*!40000 ALTER TABLE "cake_sessions" DISABLE KEYS */;
/*!40000 ALTER TABLE "cake_sessions" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "cerebrates"
--

DROP TABLE IF EXISTS "cerebrates";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "cerebrates" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "url" varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  "authkey" varbinary(255) NOT NULL,
  "open" tinyint(1) DEFAULT '0',
  "org_id" int NOT NULL,
  "pull_orgs" tinyint(1) DEFAULT '0',
  "pull_sharing_groups" tinyint(1) DEFAULT '0',
  "self_signed" tinyint(1) DEFAULT '0',
  "cert_file" varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  "client_cert_file" varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  "internal" tinyint(1) NOT NULL DEFAULT '0',
  "skip_proxy" tinyint(1) NOT NULL DEFAULT '0',
  "description" text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY ("id"),
  KEY "url" ("url"),
  KEY "org_id" ("org_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "cerebrates"
--

LOCK TABLES "cerebrates" WRITE;
/*!40000 ALTER TABLE "cerebrates" DISABLE KEYS */;
/*!40000 ALTER TABLE "cerebrates" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "correlation_exclusions"
--

DROP TABLE IF EXISTS "correlation_exclusions";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "correlation_exclusions" (
  "id" int NOT NULL AUTO_INCREMENT,
  "value" text COLLATE utf8mb4_unicode_ci NOT NULL,
  "from_json" tinyint(1) DEFAULT '0',
  "comment" text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY ("id"),
  UNIQUE KEY "value" ("value"(191))
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "correlation_exclusions"
--

LOCK TABLES "correlation_exclusions" WRITE;
/*!40000 ALTER TABLE "correlation_exclusions" DISABLE KEYS */;
/*!40000 ALTER TABLE "correlation_exclusions" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "correlation_values"
--

DROP TABLE IF EXISTS "correlation_values";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "correlation_values" (
  "id" int unsigned NOT NULL AUTO_INCREMENT,
  "value" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "value" ("value")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "correlation_values"
--

LOCK TABLES "correlation_values" WRITE;
/*!40000 ALTER TABLE "correlation_values" DISABLE KEYS */;
/*!40000 ALTER TABLE "correlation_values" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "correlations"
--

DROP TABLE IF EXISTS "correlations";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "correlations" (
  "id" int NOT NULL AUTO_INCREMENT,
  "value" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "1_event_id" int NOT NULL,
  "1_attribute_id" int NOT NULL,
  "event_id" int NOT NULL,
  "attribute_id" int NOT NULL,
  "org_id" int NOT NULL,
  "distribution" tinyint NOT NULL,
  "a_distribution" tinyint NOT NULL,
  "sharing_group_id" int NOT NULL,
  "a_sharing_group_id" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "event_id" ("event_id"),
  KEY "1_event_id" ("1_event_id"),
  KEY "attribute_id" ("attribute_id"),
  KEY "1_attribute_id" ("1_attribute_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "correlations"
--

LOCK TABLES "correlations" WRITE;
/*!40000 ALTER TABLE "correlations" DISABLE KEYS */;
/*!40000 ALTER TABLE "correlations" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "cryptographic_keys"
--

DROP TABLE IF EXISTS "cryptographic_keys";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "cryptographic_keys" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "type" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "parent_id" int NOT NULL,
  "parent_type" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "key_data" text COLLATE utf8mb4_unicode_ci,
  "revoked" tinyint(1) NOT NULL DEFAULT '0',
  "fingerprint" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  PRIMARY KEY ("id"),
  KEY "uuid" ("uuid"),
  KEY "type" ("type"),
  KEY "parent_id" ("parent_id"),
  KEY "parent_type" ("parent_type"),
  KEY "fingerprint" ("fingerprint")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "cryptographic_keys"
--

LOCK TABLES "cryptographic_keys" WRITE;
/*!40000 ALTER TABLE "cryptographic_keys" DISABLE KEYS */;
/*!40000 ALTER TABLE "cryptographic_keys" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "dashboards"
--

DROP TABLE IF EXISTS "dashboards";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "dashboards" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "name" varchar(191) NOT NULL,
  "description" text,
  "default" tinyint(1) NOT NULL DEFAULT '0',
  "selectable" tinyint(1) NOT NULL DEFAULT '0',
  "user_id" int NOT NULL DEFAULT '0',
  "restrict_to_org_id" int NOT NULL DEFAULT '0',
  "restrict_to_role_id" int NOT NULL DEFAULT '0',
  "restrict_to_permission_flag" varchar(191) NOT NULL DEFAULT '',
  "value" text,
  "timestamp" int NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "user_id" ("user_id"),
  KEY "restrict_to_org_id" ("restrict_to_org_id"),
  KEY "restrict_to_permission_flag" ("restrict_to_permission_flag")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "dashboards"
--

LOCK TABLES "dashboards" WRITE;
/*!40000 ALTER TABLE "dashboards" DISABLE KEYS */;
/*!40000 ALTER TABLE "dashboards" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "decaying_model_mappings"
--

DROP TABLE IF EXISTS "decaying_model_mappings";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "decaying_model_mappings" (
  "id" int NOT NULL AUTO_INCREMENT,
  "attribute_type" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "model_id" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "model_id" ("model_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "decaying_model_mappings"
--

LOCK TABLES "decaying_model_mappings" WRITE;
/*!40000 ALTER TABLE "decaying_model_mappings" DISABLE KEYS */;
/*!40000 ALTER TABLE "decaying_model_mappings" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "decaying_models"
--

DROP TABLE IF EXISTS "decaying_models";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "decaying_models" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "parameters" text,
  "attribute_types" text,
  "description" text,
  "org_id" int DEFAULT NULL,
  "enabled" tinyint(1) NOT NULL DEFAULT '0',
  "all_orgs" tinyint(1) NOT NULL DEFAULT '1',
  "ref" text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  "formula" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "version" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  "default" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "org_id" ("org_id"),
  KEY "enabled" ("enabled"),
  KEY "all_orgs" ("all_orgs"),
  KEY "version" ("version")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "decaying_models"
--

LOCK TABLES "decaying_models" WRITE;
/*!40000 ALTER TABLE "decaying_models" DISABLE KEYS */;
/*!40000 ALTER TABLE "decaying_models" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "default_correlations"
--

DROP TABLE IF EXISTS "default_correlations";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "default_correlations" (
  "id" int unsigned NOT NULL AUTO_INCREMENT,
  "attribute_id" int unsigned NOT NULL,
  "object_id" int unsigned NOT NULL,
  "event_id" int unsigned NOT NULL,
  "org_id" int unsigned NOT NULL,
  "distribution" tinyint NOT NULL,
  "object_distribution" tinyint NOT NULL,
  "event_distribution" tinyint NOT NULL,
  "sharing_group_id" int unsigned NOT NULL DEFAULT '0',
  "object_sharing_group_id" int unsigned NOT NULL DEFAULT '0',
  "event_sharing_group_id" int unsigned NOT NULL DEFAULT '0',
  "1_attribute_id" int unsigned NOT NULL,
  "1_object_id" int unsigned NOT NULL,
  "1_event_id" int unsigned NOT NULL,
  "1_org_id" int unsigned NOT NULL,
  "1_distribution" tinyint NOT NULL,
  "1_object_distribution" tinyint NOT NULL,
  "1_event_distribution" tinyint NOT NULL,
  "1_sharing_group_id" int unsigned NOT NULL DEFAULT '0',
  "1_object_sharing_group_id" int unsigned NOT NULL DEFAULT '0',
  "1_event_sharing_group_id" int unsigned NOT NULL DEFAULT '0',
  "value_id" int unsigned NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "unique_correlation" ("attribute_id","1_attribute_id","value_id"),
  KEY "event_id" ("event_id"),
  KEY "attribute_id" ("attribute_id"),
  KEY "object_id" ("object_id"),
  KEY "1_event_id" ("1_event_id"),
  KEY "1_attribute_id" ("1_attribute_id"),
  KEY "1_object_id" ("1_object_id"),
  KEY "value_id" ("value_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "default_correlations"
--

LOCK TABLES "default_correlations" WRITE;
/*!40000 ALTER TABLE "default_correlations" DISABLE KEYS */;
/*!40000 ALTER TABLE "default_correlations" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "event_blocklists"
--

DROP TABLE IF EXISTS "event_blocklists";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "event_blocklists" (
  "id" int NOT NULL AUTO_INCREMENT,
  "event_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "created" datetime NOT NULL,
  "event_info" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "comment" text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  "event_orgc" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "event_uuid" ("event_uuid"),
  KEY "event_orgc" ("event_orgc")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "event_blocklists"
--

LOCK TABLES "event_blocklists" WRITE;
/*!40000 ALTER TABLE "event_blocklists" DISABLE KEYS */;
/*!40000 ALTER TABLE "event_blocklists" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "event_delegations"
--

DROP TABLE IF EXISTS "event_delegations";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "event_delegations" (
  "id" int NOT NULL AUTO_INCREMENT,
  "org_id" int NOT NULL,
  "requester_org_id" int NOT NULL,
  "event_id" int NOT NULL,
  "message" text,
  "distribution" tinyint NOT NULL DEFAULT '-1',
  "sharing_group_id" int DEFAULT NULL,
  PRIMARY KEY ("id"),
  KEY "org_id" ("org_id"),
  KEY "event_id" ("event_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "event_delegations"
--

LOCK TABLES "event_delegations" WRITE;
/*!40000 ALTER TABLE "event_delegations" DISABLE KEYS */;
/*!40000 ALTER TABLE "event_delegations" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "event_graph"
--

DROP TABLE IF EXISTS "event_graph";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "event_graph" (
  "id" int NOT NULL AUTO_INCREMENT,
  "event_id" int NOT NULL,
  "user_id" int NOT NULL,
  "org_id" int NOT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "network_name" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  "network_json" mediumtext NOT NULL,
  "preview_img" mediumtext,
  PRIMARY KEY ("id"),
  KEY "event_id" ("event_id"),
  KEY "user_id" ("user_id"),
  KEY "org_id" ("org_id"),
  KEY "timestamp" ("timestamp")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "event_graph"
--

LOCK TABLES "event_graph" WRITE;
/*!40000 ALTER TABLE "event_graph" DISABLE KEYS */;
/*!40000 ALTER TABLE "event_graph" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "event_locks"
--

DROP TABLE IF EXISTS "event_locks";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "event_locks" (
  "id" int NOT NULL AUTO_INCREMENT,
  "event_id" int NOT NULL,
  "user_id" int NOT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "event_id" ("event_id"),
  KEY "user_id" ("user_id"),
  KEY "timestamp" ("timestamp")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "event_locks"
--

LOCK TABLES "event_locks" WRITE;
/*!40000 ALTER TABLE "event_locks" DISABLE KEYS */;
/*!40000 ALTER TABLE "event_locks" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "event_reports"
--

DROP TABLE IF EXISTS "event_reports";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "event_reports" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "event_id" int NOT NULL,
  "name" varchar(255) NOT NULL,
  "content" text,
  "distribution" tinyint NOT NULL DEFAULT '0',
  "sharing_group_id" int DEFAULT NULL,
  "timestamp" int NOT NULL,
  "deleted" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  UNIQUE KEY "u_uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "event_id" ("event_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "event_reports"
--

LOCK TABLES "event_reports" WRITE;
/*!40000 ALTER TABLE "event_reports" DISABLE KEYS */;
/*!40000 ALTER TABLE "event_reports" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "event_tags"
--

DROP TABLE IF EXISTS "event_tags";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "event_tags" (
  "id" int NOT NULL AUTO_INCREMENT,
  "event_id" int NOT NULL,
  "tag_id" int NOT NULL,
  "local" tinyint(1) NOT NULL DEFAULT '0',
  "relationship_type" varchar(191) DEFAULT '',
  PRIMARY KEY ("id"),
  KEY "event_id" ("event_id"),
  KEY "tag_id" ("tag_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "event_tags"
--

LOCK TABLES "event_tags" WRITE;
/*!40000 ALTER TABLE "event_tags" DISABLE KEYS */;
/*!40000 ALTER TABLE "event_tags" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "events"
--

DROP TABLE IF EXISTS "events";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "events" (
  "id" int NOT NULL AUTO_INCREMENT,
  "org_id" int NOT NULL,
  "date" date NOT NULL,
  "info" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "user_id" int NOT NULL,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "published" tinyint(1) NOT NULL DEFAULT '0',
  "analysis" tinyint NOT NULL,
  "attribute_count" int unsigned DEFAULT '0',
  "orgc_id" int NOT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "distribution" tinyint NOT NULL DEFAULT '0',
  "sharing_group_id" int NOT NULL,
  "proposal_email_lock" tinyint(1) NOT NULL DEFAULT '0',
  "locked" tinyint(1) NOT NULL DEFAULT '0',
  "threat_level_id" int NOT NULL,
  "publish_timestamp" int NOT NULL DEFAULT '0',
  "sighting_timestamp" int NOT NULL DEFAULT '0',
  "disable_correlation" tinyint(1) NOT NULL DEFAULT '0',
  "extends_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT '',
  "protected" tinyint(1) DEFAULT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  KEY "info" ("info"(255)),
  KEY "sharing_group_id" ("sharing_group_id"),
  KEY "org_id" ("org_id"),
  KEY "orgc_id" ("orgc_id"),
  KEY "extends_uuid" ("extends_uuid")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "events"
--

LOCK TABLES "events" WRITE;
/*!40000 ALTER TABLE "events" DISABLE KEYS */;
/*!40000 ALTER TABLE "events" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "favourite_tags"
--

DROP TABLE IF EXISTS "favourite_tags";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "favourite_tags" (
  "id" int NOT NULL AUTO_INCREMENT,
  "tag_id" int NOT NULL,
  "user_id" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "user_id" ("user_id"),
  KEY "tag_id" ("tag_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "favourite_tags"
--

LOCK TABLES "favourite_tags" WRITE;
/*!40000 ALTER TABLE "favourite_tags" DISABLE KEYS */;
/*!40000 ALTER TABLE "favourite_tags" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "feeds"
--

DROP TABLE IF EXISTS "feeds";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "feeds" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "provider" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "url" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "rules" text CHARACTER SET utf8 COLLATE utf8_bin,
  "enabled" tinyint(1) DEFAULT '0',
  "distribution" tinyint NOT NULL DEFAULT '0',
  "sharing_group_id" int NOT NULL DEFAULT '0',
  "tag_id" int NOT NULL DEFAULT '0',
  "default" tinyint(1) DEFAULT '0',
  "source_format" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT 'misp',
  "fixed_event" tinyint(1) NOT NULL DEFAULT '0',
  "delta_merge" tinyint(1) NOT NULL DEFAULT '0',
  "event_id" int NOT NULL DEFAULT '0',
  "publish" tinyint(1) NOT NULL DEFAULT '0',
  "override_ids" tinyint(1) NOT NULL DEFAULT '0',
  "settings" text,
  "input_source" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT 'network',
  "delete_local_file" tinyint(1) DEFAULT '0',
  "lookup_visible" tinyint(1) DEFAULT '0',
  "headers" text CHARACTER SET utf8 COLLATE utf8_bin,
  "caching_enabled" tinyint(1) NOT NULL DEFAULT '0',
  "force_to_ids" tinyint(1) NOT NULL DEFAULT '0',
  "orgc_id" int NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "input_source" ("input_source"),
  KEY "orgc_id" ("orgc_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "feeds"
--

LOCK TABLES "feeds" WRITE;
/*!40000 ALTER TABLE "feeds" DISABLE KEYS */;
INSERT INTO "feeds" VALUES (1,'CIRCL OSINT Feed','CIRCL','https://www.circl.lu/doc/misp/feed-osint',NULL,0,3,0,0,1,'misp',0,0,0,0,0,NULL,'network',0,0,NULL,0,0,0),(2,'The Botvrij.eu Data','Botvrij.eu','https://www.botvrij.eu/data/feed-osint',NULL,0,3,0,0,1,'misp',0,0,0,0,0,NULL,'network',0,0,NULL,0,0,0);
/*!40000 ALTER TABLE "feeds" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "fuzzy_correlate_ssdeep"
--

DROP TABLE IF EXISTS "fuzzy_correlate_ssdeep";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "fuzzy_correlate_ssdeep" (
  "id" int NOT NULL AUTO_INCREMENT,
  "chunk" varchar(12) NOT NULL,
  "attribute_id" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "chunk" ("chunk"),
  KEY "attribute_id" ("attribute_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "fuzzy_correlate_ssdeep"
--

LOCK TABLES "fuzzy_correlate_ssdeep" WRITE;
/*!40000 ALTER TABLE "fuzzy_correlate_ssdeep" DISABLE KEYS */;
/*!40000 ALTER TABLE "fuzzy_correlate_ssdeep" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "galaxies"
--

DROP TABLE IF EXISTS "galaxies";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "galaxies" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  "type" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "version" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "icon" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  "namespace" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL DEFAULT 'misp',
  "enabled" tinyint(1) NOT NULL DEFAULT '1',
  "local_only" tinyint(1) NOT NULL DEFAULT '0',
  "kill_chain_order" text COLLATE utf8_bin,
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "type" ("type"),
  KEY "namespace" ("namespace")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "galaxies"
--

LOCK TABLES "galaxies" WRITE;
/*!40000 ALTER TABLE "galaxies" DISABLE KEYS */;
/*!40000 ALTER TABLE "galaxies" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "galaxy_cluster_blocklists"
--

DROP TABLE IF EXISTS "galaxy_cluster_blocklists";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "galaxy_cluster_blocklists" (
  "id" int NOT NULL AUTO_INCREMENT,
  "cluster_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "created" datetime NOT NULL,
  "cluster_info" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "comment" text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  "cluster_orgc" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id"),
  KEY "cluster_uuid" ("cluster_uuid"),
  KEY "cluster_orgc" ("cluster_orgc")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "galaxy_cluster_blocklists"
--

LOCK TABLES "galaxy_cluster_blocklists" WRITE;
/*!40000 ALTER TABLE "galaxy_cluster_blocklists" DISABLE KEYS */;
/*!40000 ALTER TABLE "galaxy_cluster_blocklists" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "galaxy_cluster_relation_tags"
--

DROP TABLE IF EXISTS "galaxy_cluster_relation_tags";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "galaxy_cluster_relation_tags" (
  "id" int NOT NULL AUTO_INCREMENT,
  "galaxy_cluster_relation_id" int NOT NULL,
  "tag_id" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "galaxy_cluster_relation_id" ("galaxy_cluster_relation_id"),
  KEY "tag_id" ("tag_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "galaxy_cluster_relation_tags"
--

LOCK TABLES "galaxy_cluster_relation_tags" WRITE;
/*!40000 ALTER TABLE "galaxy_cluster_relation_tags" DISABLE KEYS */;
/*!40000 ALTER TABLE "galaxy_cluster_relation_tags" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "galaxy_cluster_relations"
--

DROP TABLE IF EXISTS "galaxy_cluster_relations";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "galaxy_cluster_relations" (
  "id" int NOT NULL AUTO_INCREMENT,
  "galaxy_cluster_id" int NOT NULL,
  "referenced_galaxy_cluster_id" int NOT NULL,
  "referenced_galaxy_cluster_uuid" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "referenced_galaxy_cluster_type" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "galaxy_cluster_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "distribution" tinyint NOT NULL DEFAULT '0',
  "sharing_group_id" int DEFAULT NULL,
  "default" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "galaxy_cluster_id" ("galaxy_cluster_id"),
  KEY "referenced_galaxy_cluster_id" ("referenced_galaxy_cluster_id"),
  KEY "referenced_galaxy_cluster_type" ("referenced_galaxy_cluster_type"(255)),
  KEY "galaxy_cluster_uuid" ("galaxy_cluster_uuid"),
  KEY "sharing_group_id" ("sharing_group_id"),
  KEY "default" ("default")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "galaxy_cluster_relations"
--

LOCK TABLES "galaxy_cluster_relations" WRITE;
/*!40000 ALTER TABLE "galaxy_cluster_relations" DISABLE KEYS */;
/*!40000 ALTER TABLE "galaxy_cluster_relations" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "galaxy_clusters"
--

DROP TABLE IF EXISTS "galaxy_clusters";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "galaxy_clusters" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  "collection_uuid" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "type" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "value" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "tag_name" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL DEFAULT '',
  "description" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "galaxy_id" int NOT NULL,
  "source" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  "authors" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "version" int DEFAULT '0',
  "distribution" tinyint NOT NULL DEFAULT '0',
  "sharing_group_id" int DEFAULT NULL,
  "org_id" int NOT NULL,
  "orgc_id" int NOT NULL,
  "default" tinyint(1) NOT NULL DEFAULT '0',
  "locked" tinyint(1) NOT NULL DEFAULT '0',
  "extends_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT '',
  "extends_version" int DEFAULT '0',
  "published" tinyint(1) NOT NULL DEFAULT '0',
  "deleted" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "value" ("value"(255)),
  KEY "uuid" ("uuid"),
  KEY "collection_uuid" ("collection_uuid"),
  KEY "galaxy_id" ("galaxy_id"),
  KEY "version" ("version"),
  KEY "tag_name" ("tag_name"),
  KEY "type" ("type"),
  KEY "org_id" ("org_id"),
  KEY "orgc_id" ("orgc_id"),
  KEY "sharing_group_id" ("sharing_group_id"),
  KEY "extends_uuid" ("extends_uuid"),
  KEY "extends_version" ("extends_version"),
  KEY "default" ("default")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "galaxy_clusters"
--

LOCK TABLES "galaxy_clusters" WRITE;
/*!40000 ALTER TABLE "galaxy_clusters" DISABLE KEYS */;
/*!40000 ALTER TABLE "galaxy_clusters" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "galaxy_elements"
--

DROP TABLE IF EXISTS "galaxy_elements";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "galaxy_elements" (
  "id" int NOT NULL AUTO_INCREMENT,
  "galaxy_cluster_id" int NOT NULL,
  "key" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  "value" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id"),
  KEY "key" ("key"),
  KEY "value" ("value"(255)),
  KEY "galaxy_cluster_id" ("galaxy_cluster_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "galaxy_elements"
--

LOCK TABLES "galaxy_elements" WRITE;
/*!40000 ALTER TABLE "galaxy_elements" DISABLE KEYS */;
/*!40000 ALTER TABLE "galaxy_elements" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "inbox"
--

DROP TABLE IF EXISTS "inbox";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "inbox" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "title" varchar(191) NOT NULL,
  "type" varchar(191) NOT NULL,
  "ip" varchar(191) NOT NULL,
  "user_agent" text,
  "user_agent_sha256" varchar(64) NOT NULL,
  "comment" text,
  "deleted" tinyint(1) NOT NULL DEFAULT '0',
  "timestamp" int NOT NULL,
  "store_as_file" tinyint(1) NOT NULL DEFAULT '0',
  "data" longtext,
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  KEY "title" ("title"),
  KEY "type" ("type"),
  KEY "user_agent_sha256" ("user_agent_sha256"),
  KEY "ip" ("ip"),
  KEY "timestamp" ("timestamp")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "inbox"
--

LOCK TABLES "inbox" WRITE;
/*!40000 ALTER TABLE "inbox" DISABLE KEYS */;
/*!40000 ALTER TABLE "inbox" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "jobs"
--

DROP TABLE IF EXISTS "jobs";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "jobs" (
  "id" int NOT NULL AUTO_INCREMENT,
  "worker" varchar(32) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "job_type" varchar(32) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "job_input" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "status" tinyint NOT NULL DEFAULT '0',
  "retries" int NOT NULL DEFAULT '0',
  "message" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "progress" int NOT NULL DEFAULT '0',
  "org_id" int NOT NULL DEFAULT '0',
  "process_id" varchar(36) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "date_created" datetime NOT NULL,
  "date_modified" datetime NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table "logs"
--

DROP TABLE IF EXISTS "logs";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "logs" (
  "id" int NOT NULL AUTO_INCREMENT,
  "title" text CHARACTER SET utf8 COLLATE utf8_bin,
  "created" datetime NOT NULL,
  "model" varchar(80) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "model_id" int NOT NULL,
  "action" varchar(20) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "user_id" int NOT NULL,
  "change" text CHARACTER SET utf8 COLLATE utf8_bin,
  "email" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  "org" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  "description" text CHARACTER SET utf8 COLLATE utf8_bin,
  "ip" varchar(45) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table "news"
--

DROP TABLE IF EXISTS "news";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "news" (
  "id" int NOT NULL AUTO_INCREMENT,
  "message" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "title" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "user_id" int NOT NULL,
  "date_created" int unsigned NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "news"
--

LOCK TABLES "news" WRITE;
/*!40000 ALTER TABLE "news" DISABLE KEYS */;
/*!40000 ALTER TABLE "news" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "no_acl_correlations"
--

DROP TABLE IF EXISTS "no_acl_correlations";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "no_acl_correlations" (
  "id" int unsigned NOT NULL AUTO_INCREMENT,
  "attribute_id" int unsigned NOT NULL,
  "1_attribute_id" int unsigned NOT NULL,
  "event_id" int unsigned NOT NULL,
  "1_event_id" int unsigned NOT NULL,
  "value_id" int unsigned NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "unique_correlation" ("attribute_id","1_attribute_id","value_id"),
  KEY "event_id" ("event_id"),
  KEY "1_event_id" ("1_event_id"),
  KEY "attribute_id" ("attribute_id"),
  KEY "1_attribute_id" ("1_attribute_id"),
  KEY "value_id" ("value_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "no_acl_correlations"
--

LOCK TABLES "no_acl_correlations" WRITE;
/*!40000 ALTER TABLE "no_acl_correlations" DISABLE KEYS */;
/*!40000 ALTER TABLE "no_acl_correlations" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "noticelist_entries"
--

DROP TABLE IF EXISTS "noticelist_entries";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "noticelist_entries" (
  "id" int NOT NULL AUTO_INCREMENT,
  "noticelist_id" int NOT NULL,
  "data" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY ("id"),
  KEY "noticelist_id" ("noticelist_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "noticelist_entries"
--

LOCK TABLES "noticelist_entries" WRITE;
/*!40000 ALTER TABLE "noticelist_entries" DISABLE KEYS */;
/*!40000 ALTER TABLE "noticelist_entries" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "noticelists"
--

DROP TABLE IF EXISTS "noticelists";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "noticelists" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "expanded_name" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "ref" text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  "geographical_area" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  "version" int NOT NULL DEFAULT '1',
  "enabled" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "name" ("name"),
  KEY "geographical_area" ("geographical_area")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "noticelists"
--

LOCK TABLES "noticelists" WRITE;
/*!40000 ALTER TABLE "noticelists" DISABLE KEYS */;
/*!40000 ALTER TABLE "noticelists" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "notification_logs"
--

DROP TABLE IF EXISTS "notification_logs";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "notification_logs" (
  "id" int NOT NULL AUTO_INCREMENT,
  "org_id" int NOT NULL,
  "type" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "org_id" ("org_id"),
  KEY "type" ("type")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "notification_logs"
--

LOCK TABLES "notification_logs" WRITE;
/*!40000 ALTER TABLE "notification_logs" DISABLE KEYS */;
/*!40000 ALTER TABLE "notification_logs" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "object_references"
--

DROP TABLE IF EXISTS "object_references";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "object_references" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "object_id" int NOT NULL,
  "event_id" int NOT NULL,
  "source_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "referenced_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "referenced_id" int NOT NULL,
  "referenced_type" int NOT NULL DEFAULT '0',
  "relationship_type" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  "comment" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "deleted" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  KEY "object_id" ("object_id"),
  KEY "referenced_id" ("referenced_id"),
  KEY "event_id" ("event_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "object_references"
--

LOCK TABLES "object_references" WRITE;
/*!40000 ALTER TABLE "object_references" DISABLE KEYS */;
/*!40000 ALTER TABLE "object_references" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "object_relationships"
--

DROP TABLE IF EXISTS "object_relationships";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "object_relationships" (
  "id" int NOT NULL AUTO_INCREMENT,
  "version" int NOT NULL,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "format" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id"),
  KEY "name" ("name")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "object_relationships"
--

LOCK TABLES "object_relationships" WRITE;
/*!40000 ALTER TABLE "object_relationships" DISABLE KEYS */;
/*!40000 ALTER TABLE "object_relationships" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "object_template_elements"
--

DROP TABLE IF EXISTS "object_template_elements";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "object_template_elements" (
  "id" int NOT NULL AUTO_INCREMENT,
  "object_template_id" int NOT NULL,
  "object_relation" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "type" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "ui-priority" int NOT NULL,
  "categories" text CHARACTER SET utf8 COLLATE utf8_bin,
  "sane_default" text CHARACTER SET utf8 COLLATE utf8_bin,
  "values_list" text CHARACTER SET utf8 COLLATE utf8_bin,
  "description" text CHARACTER SET utf8 COLLATE utf8_bin,
  "disable_correlation" tinyint(1) DEFAULT NULL,
  "multiple" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "object_relation" ("object_relation"),
  KEY "type" ("type"),
  KEY "object_template_id" ("object_template_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "object_template_elements"
--

LOCK TABLES "object_template_elements" WRITE;
/*!40000 ALTER TABLE "object_template_elements" DISABLE KEYS */;
/*!40000 ALTER TABLE "object_template_elements" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "object_templates"
--

DROP TABLE IF EXISTS "object_templates";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "object_templates" (
  "id" int NOT NULL AUTO_INCREMENT,
  "user_id" int NOT NULL,
  "org_id" int NOT NULL,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  "meta-category" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_bin,
  "version" int NOT NULL,
  "requirements" text CHARACTER SET utf8 COLLATE utf8_bin,
  "fixed" tinyint(1) NOT NULL DEFAULT '0',
  "active" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "user_id" ("user_id"),
  KEY "org_id" ("org_id"),
  KEY "uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "meta-category" ("meta-category")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "object_templates"
--

LOCK TABLES "object_templates" WRITE;
/*!40000 ALTER TABLE "object_templates" DISABLE KEYS */;
/*!40000 ALTER TABLE "object_templates" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "objects"
--

DROP TABLE IF EXISTS "objects";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "objects" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  "meta-category" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  "template_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "template_version" int NOT NULL,
  "event_id" int NOT NULL,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "distribution" tinyint NOT NULL DEFAULT '0',
  "sharing_group_id" int DEFAULT NULL,
  "comment" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "deleted" tinyint(1) NOT NULL DEFAULT '0',
  "first_seen" bigint DEFAULT NULL,
  "last_seen" bigint DEFAULT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "template_uuid" ("template_uuid"),
  KEY "template_version" ("template_version"),
  KEY "meta-category" ("meta-category"),
  KEY "event_id" ("event_id"),
  KEY "timestamp" ("timestamp"),
  KEY "distribution" ("distribution"),
  KEY "sharing_group_id" ("sharing_group_id"),
  KEY "first_seen" ("first_seen"),
  KEY "last_seen" ("last_seen")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "objects"
--

LOCK TABLES "objects" WRITE;
/*!40000 ALTER TABLE "objects" DISABLE KEYS */;
/*!40000 ALTER TABLE "objects" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "org_blocklists"
--

DROP TABLE IF EXISTS "org_blocklists";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "org_blocklists" (
  "id" int NOT NULL AUTO_INCREMENT,
  "org_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "created" datetime NOT NULL,
  "org_name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "comment" text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  PRIMARY KEY ("id"),
  UNIQUE KEY "org_uuid" ("org_uuid"),
  KEY "org_name" ("org_name")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "org_blocklists"
--

LOCK TABLES "org_blocklists" WRITE;
/*!40000 ALTER TABLE "org_blocklists" DISABLE KEYS */;
INSERT INTO "org_blocklists" VALUES (1,'58d38339-7b24-4386-b4b4-4c0f950d210f','2023-04-05 08:49:53','Setec Astrononomy','default example'),(2,'58d38326-eda8-443a-9fa8-4e12950d210f','2023-04-05 08:49:53','Acme Finance','default example');
/*!40000 ALTER TABLE "org_blocklists" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "organisations"
--

DROP TABLE IF EXISTS "organisations";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "organisations" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  "date_created" datetime NOT NULL,
  "date_modified" datetime NOT NULL,
  "description" text COLLATE utf8_bin,
  "type" varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  "nationality" varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  "sector" varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
  "created_by" int NOT NULL DEFAULT '0',
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "contacts" text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  "local" tinyint(1) NOT NULL DEFAULT '0',
  "restricted_to_domain" text CHARACTER SET utf8 COLLATE utf8_bin,
  "landingpage" text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  PRIMARY KEY ("id"),
  UNIQUE KEY "name" ("name"),
  UNIQUE KEY "uuid" ("uuid")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table "over_correlating_values"
--

DROP TABLE IF EXISTS "over_correlating_values";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "over_correlating_values" (
  "id" int unsigned NOT NULL AUTO_INCREMENT,
  "value" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "occurrence" int unsigned DEFAULT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "value" ("value"),
  KEY "occurrence" ("occurrence")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "over_correlating_values"
--

LOCK TABLES "over_correlating_values" WRITE;
/*!40000 ALTER TABLE "over_correlating_values" DISABLE KEYS */;
/*!40000 ALTER TABLE "over_correlating_values" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "posts"
--

DROP TABLE IF EXISTS "posts";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "posts" (
  "id" int NOT NULL AUTO_INCREMENT,
  "date_created" datetime NOT NULL,
  "date_modified" datetime NOT NULL,
  "user_id" int NOT NULL,
  "contents" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "post_id" int NOT NULL DEFAULT '0',
  "thread_id" int NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "post_id" ("post_id"),
  KEY "thread_id" ("thread_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "posts"
--

LOCK TABLES "posts" WRITE;
/*!40000 ALTER TABLE "posts" DISABLE KEYS */;
/*!40000 ALTER TABLE "posts" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "regexp"
--

DROP TABLE IF EXISTS "regexp";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "regexp" (
  "id" int NOT NULL AUTO_INCREMENT,
  "regexp" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "replacement" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "type" varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT 'ALL',
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "regexp"
--

LOCK TABLES "regexp" WRITE;
/*!40000 ALTER TABLE "regexp" DISABLE KEYS */;
INSERT INTO "regexp" VALUES (1,'/.:.ProgramData./i','%ALLUSERSPROFILE%\\\\','ALL'),(2,'/.:.Documents and Settings.All Users./i','%ALLUSERSPROFILE%\\\\','ALL'),(3,'/.:.Program Files.Common Files./i','%COMMONPROGRAMFILES%\\\\','ALL'),(4,'/.:.Program Files (x86).Common Files./i','%COMMONPROGRAMFILES(x86)%\\\\','ALL'),(5,'/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i','%TEMP%\\\\','ALL'),(6,'/.:.ProgramData./i','%PROGRAMDATA%\\\\','ALL'),(7,'/.:.Program Files./i','%PROGRAMFILES%\\\\','ALL'),(8,'/.:.Program Files (x86)./i','%PROGRAMFILES(X86)%\\\\','ALL'),(9,'/.:.Users.Public./i','%PUBLIC%\\\\','ALL'),(10,'/.:.Documents and Settings\\\\(.*?)\\\\Local Settings.Temp./i','%TEMP%\\\\','ALL'),(11,'/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i','%TEMP%\\\\','ALL'),(12,'/.:.Users\\\\(.*?)\\\\AppData.Local./i','%LOCALAPPDATA%\\\\','ALL'),(13,'/.:.Users\\\\(.*?)\\\\AppData.Roaming./i','%APPDATA%\\\\','ALL'),(14,'/.:.Users\\\\(.*?)\\\\Application Data./i','%APPDATA%\\\\','ALL'),(15,'/.:.Windows\\\\(.*?)\\\\Application Data./i','%APPDATA%\\\\','ALL'),(16,'/.:.Users\\\\(.*?)\\\\/i','%USERPROFILE%\\\\','ALL'),(17,'/.:.DOCUME~1.\\\\(.*?)\\\\/i','%USERPROFILE%\\\\','ALL'),(18,'/.:.Documents and Settings\\\\(.*?)\\\\/i','%USERPROFILE%\\\\','ALL'),(19,'/.:.Windows./i','%WINDIR%\\\\','ALL'),(20,'/.:.Windows./i','%WINDIR%\\\\','ALL'),(21,'/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}/i','HKCU','ALL'),(22,'/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}/i','HKCU','ALL'),(23,'/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}/i','HKCU','ALL'),(24,'/.REGISTRY.MACHINE./i','HKLM\\\\','ALL'),(25,'/.Registry.Machine./i','HKLM\\\\','ALL'),(26,'/%USERPROFILE%.Application Data.Microsoft.UProof/i','','ALL'),(27,'/%USERPROFILE%.Local Settings.History/i','','ALL'),(28,'/%APPDATA%.Microsoft.UProof/i ','','ALL'),(29,'/%LOCALAPPDATA%.Microsoft.Windows.Temporary Internet Files/i','','ALL');
/*!40000 ALTER TABLE "regexp" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "rest_client_histories"
--

DROP TABLE IF EXISTS "rest_client_histories";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "rest_client_histories" (
  "id" int NOT NULL AUTO_INCREMENT,
  "org_id" int NOT NULL,
  "user_id" int NOT NULL,
  "headers" text,
  "body" text,
  "url" text,
  "http_method" varchar(255) DEFAULT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "use_full_path" tinyint(1) DEFAULT '0',
  "show_result" tinyint(1) DEFAULT '0',
  "skip_ssl" tinyint(1) DEFAULT '0',
  "outcome" int NOT NULL,
  "bookmark" tinyint(1) NOT NULL DEFAULT '0',
  "bookmark_name" varchar(255) DEFAULT '',
  PRIMARY KEY ("id"),
  KEY "org_id" ("org_id"),
  KEY "user_id" ("user_id"),
  KEY "timestamp" ("timestamp")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "rest_client_histories"
--

LOCK TABLES "rest_client_histories" WRITE;
/*!40000 ALTER TABLE "rest_client_histories" DISABLE KEYS */;
/*!40000 ALTER TABLE "rest_client_histories" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "roles"
--

DROP TABLE IF EXISTS "roles";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "roles" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "created" datetime DEFAULT NULL,
  "modified" datetime DEFAULT NULL,
  "perm_add" tinyint(1) DEFAULT NULL,
  "perm_modify" tinyint(1) DEFAULT NULL,
  "perm_modify_org" tinyint(1) DEFAULT NULL,
  "perm_publish" tinyint(1) DEFAULT NULL,
  "perm_delegate" tinyint(1) NOT NULL DEFAULT '0',
  "perm_sync" tinyint(1) DEFAULT NULL,
  "perm_admin" tinyint(1) DEFAULT NULL,
  "perm_audit" tinyint(1) DEFAULT NULL,
  "perm_full" tinyint(1) DEFAULT NULL,
  "perm_auth" tinyint(1) NOT NULL DEFAULT '0',
  "perm_site_admin" tinyint(1) NOT NULL DEFAULT '0',
  "perm_regexp_access" tinyint(1) NOT NULL DEFAULT '0',
  "perm_tagger" tinyint(1) NOT NULL DEFAULT '0',
  "perm_template" tinyint(1) NOT NULL DEFAULT '0',
  "perm_sharing_group" tinyint(1) NOT NULL DEFAULT '0',
  "perm_tag_editor" tinyint(1) NOT NULL DEFAULT '0',
  "perm_sighting" tinyint(1) NOT NULL DEFAULT '0',
  "perm_object_template" tinyint(1) NOT NULL DEFAULT '0',
  "default_role" tinyint(1) NOT NULL DEFAULT '0',
  "memory_limit" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT '',
  "max_execution_time" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT '',
  "restricted_to_site_admin" tinyint(1) NOT NULL DEFAULT '0',
  "perm_publish_zmq" tinyint(1) NOT NULL DEFAULT '0',
  "perm_publish_kafka" tinyint(1) NOT NULL DEFAULT '0',
  "perm_decaying" tinyint(1) NOT NULL DEFAULT '0',
  "enforce_rate_limit" tinyint(1) NOT NULL DEFAULT '0',
  "rate_limit_count" int NOT NULL DEFAULT '0',
  "perm_galaxy_editor" tinyint(1) NOT NULL DEFAULT '0',
  "perm_warninglist" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "roles"
--

LOCK TABLES "roles" WRITE;
/*!40000 ALTER TABLE "roles" DISABLE KEYS */;
INSERT INTO "roles" VALUES (1,'admin','2023-04-05 08:49:53','2023-04-05 08:49:53',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,'','',0,1,1,1,0,0,1,0),(2,'Org Admin','2023-04-05 08:49:53','2023-04-05 08:49:53',1,1,1,1,1,0,1,1,0,1,0,0,1,1,1,1,1,0,0,'','',0,1,1,1,0,0,1,0),(3,'User','2023-04-05 08:49:53','2023-04-05 08:49:53',1,1,1,0,0,0,0,1,0,1,0,0,1,0,0,0,1,0,1,'','',0,0,0,1,0,0,0,0),(4,'Publisher','2023-04-05 08:49:53','2023-04-05 08:49:53',1,1,1,1,1,0,0,1,0,1,0,0,1,0,0,0,1,0,0,'','',0,1,1,1,0,0,0,0),(5,'Sync user','2023-04-05 08:49:53','2023-04-05 08:49:53',1,1,1,1,1,1,0,1,0,1,0,0,1,0,1,1,1,0,0,'','',0,1,1,1,0,0,1,0),(6,'Read Only','2023-04-05 08:49:53','2023-04-05 08:49:53',0,0,0,0,0,0,0,1,0,1,0,0,0,0,0,0,0,0,0,'','',0,0,0,0,0,0,0,0);
/*!40000 ALTER TABLE "roles" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "servers"
--

DROP TABLE IF EXISTS "servers";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "servers" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "url" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "authkey" varbinary(255) NOT NULL,
  "org_id" int NOT NULL,
  "push" tinyint(1) NOT NULL,
  "pull" tinyint(1) NOT NULL,
  "push_sightings" tinyint(1) NOT NULL DEFAULT '0',
  "push_galaxy_clusters" tinyint(1) NOT NULL DEFAULT '0',
  "pull_galaxy_clusters" tinyint(1) NOT NULL DEFAULT '0',
  "lastpulledid" int DEFAULT NULL,
  "lastpushedid" int DEFAULT NULL,
  "organization" varchar(10) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "remote_org_id" int NOT NULL,
  "publish_without_email" tinyint(1) NOT NULL DEFAULT '0',
  "unpublish_event" tinyint(1) NOT NULL DEFAULT '0',
  "self_signed" tinyint(1) NOT NULL,
  "pull_rules" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "push_rules" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "cert_file" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "client_cert_file" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "internal" tinyint(1) NOT NULL DEFAULT '0',
  "skip_proxy" tinyint(1) NOT NULL DEFAULT '0',
  "remove_missing_tags" tinyint(1) NOT NULL DEFAULT '0',
  "caching_enabled" tinyint(1) NOT NULL DEFAULT '0',
  "priority" int NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "org_id" ("org_id"),
  KEY "priority" ("priority"),
  KEY "remote_org_id" ("remote_org_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "servers"
--

LOCK TABLES "servers" WRITE;
/*!40000 ALTER TABLE "servers" DISABLE KEYS */;
/*!40000 ALTER TABLE "servers" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "shadow_attribute_correlations"
--

DROP TABLE IF EXISTS "shadow_attribute_correlations";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "shadow_attribute_correlations" (
  "id" int NOT NULL AUTO_INCREMENT,
  "org_id" int NOT NULL,
  "value" text NOT NULL,
  "distribution" tinyint NOT NULL,
  "a_distribution" tinyint NOT NULL,
  "sharing_group_id" int DEFAULT NULL,
  "a_sharing_group_id" int DEFAULT NULL,
  "attribute_id" int NOT NULL,
  "1_shadow_attribute_id" int NOT NULL,
  "event_id" int NOT NULL,
  "1_event_id" int NOT NULL,
  "info" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id"),
  KEY "org_id" ("org_id"),
  KEY "attribute_id" ("attribute_id"),
  KEY "a_sharing_group_id" ("a_sharing_group_id"),
  KEY "event_id" ("event_id"),
  KEY "1_event_id" ("1_event_id"),
  KEY "sharing_group_id" ("sharing_group_id"),
  KEY "1_shadow_attribute_id" ("1_shadow_attribute_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "shadow_attribute_correlations"
--

LOCK TABLES "shadow_attribute_correlations" WRITE;
/*!40000 ALTER TABLE "shadow_attribute_correlations" DISABLE KEYS */;
/*!40000 ALTER TABLE "shadow_attribute_correlations" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "shadow_attributes"
--

DROP TABLE IF EXISTS "shadow_attributes";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "shadow_attributes" (
  "id" int NOT NULL AUTO_INCREMENT,
  "old_id" int DEFAULT '0',
  "event_id" int NOT NULL,
  "type" varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "category" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "value1" text CHARACTER SET utf8 COLLATE utf8_bin,
  "to_ids" tinyint(1) NOT NULL DEFAULT '1',
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "value2" text CHARACTER SET utf8 COLLATE utf8_bin,
  "org_id" int NOT NULL,
  "email" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  "event_org_id" int NOT NULL,
  "comment" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "event_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "deleted" tinyint(1) NOT NULL DEFAULT '0',
  "timestamp" int NOT NULL DEFAULT '0',
  "proposal_to_delete" tinyint(1) NOT NULL DEFAULT '0',
  "disable_correlation" tinyint(1) NOT NULL DEFAULT '0',
  "first_seen" bigint DEFAULT NULL,
  "last_seen" bigint DEFAULT NULL,
  PRIMARY KEY ("id"),
  KEY "event_id" ("event_id"),
  KEY "event_uuid" ("event_uuid"),
  KEY "event_org_id" ("event_org_id"),
  KEY "uuid" ("uuid"),
  KEY "old_id" ("old_id"),
  KEY "value1" ("value1"(255)),
  KEY "value2" ("value2"(255)),
  KEY "type" ("type"),
  KEY "category" ("category"),
  KEY "first_seen" ("first_seen"),
  KEY "last_seen" ("last_seen")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "shadow_attributes"
--

LOCK TABLES "shadow_attributes" WRITE;
/*!40000 ALTER TABLE "shadow_attributes" DISABLE KEYS */;
/*!40000 ALTER TABLE "shadow_attributes" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "sharing_group_blueprints"
--

DROP TABLE IF EXISTS "sharing_group_blueprints";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "sharing_group_blueprints" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "name" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "user_id" int NOT NULL,
  "org_id" int NOT NULL,
  "sharing_group_id" int DEFAULT NULL,
  "rules" text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY ("id"),
  KEY "uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "org_id" ("org_id"),
  KEY "sharing_group_id" ("sharing_group_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "sharing_group_blueprints"
--

LOCK TABLES "sharing_group_blueprints" WRITE;
/*!40000 ALTER TABLE "sharing_group_blueprints" DISABLE KEYS */;
/*!40000 ALTER TABLE "sharing_group_blueprints" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "sharing_group_orgs"
--

DROP TABLE IF EXISTS "sharing_group_orgs";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "sharing_group_orgs" (
  "id" int NOT NULL AUTO_INCREMENT,
  "sharing_group_id" int NOT NULL,
  "org_id" int NOT NULL,
  "extend" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  KEY "org_id" ("org_id"),
  KEY "sharing_group_id" ("sharing_group_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "sharing_group_orgs"
--

LOCK TABLES "sharing_group_orgs" WRITE;
/*!40000 ALTER TABLE "sharing_group_orgs" DISABLE KEYS */;
/*!40000 ALTER TABLE "sharing_group_orgs" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "sharing_group_servers"
--

DROP TABLE IF EXISTS "sharing_group_servers";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "sharing_group_servers" (
  "id" int NOT NULL AUTO_INCREMENT,
  "sharing_group_id" int NOT NULL,
  "server_id" int NOT NULL,
  "all_orgs" tinyint(1) NOT NULL,
  PRIMARY KEY ("id"),
  KEY "server_id" ("server_id"),
  KEY "sharing_group_id" ("sharing_group_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "sharing_group_servers"
--

LOCK TABLES "sharing_group_servers" WRITE;
/*!40000 ALTER TABLE "sharing_group_servers" DISABLE KEYS */;
/*!40000 ALTER TABLE "sharing_group_servers" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "sharing_groups"
--

DROP TABLE IF EXISTS "sharing_groups";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "sharing_groups" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "releasability" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "organisation_uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "org_id" int NOT NULL,
  "sync_user_id" int NOT NULL DEFAULT '0',
  "active" tinyint(1) NOT NULL,
  "created" datetime NOT NULL,
  "modified" datetime NOT NULL,
  "local" tinyint(1) NOT NULL,
  "roaming" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  UNIQUE KEY "name" ("name"),
  KEY "org_id" ("org_id"),
  KEY "sync_user_id" ("sync_user_id"),
  KEY "organisation_uuid" ("organisation_uuid")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "sharing_groups"
--

LOCK TABLES "sharing_groups" WRITE;
/*!40000 ALTER TABLE "sharing_groups" DISABLE KEYS */;
/*!40000 ALTER TABLE "sharing_groups" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "sightingdb_orgs"
--

DROP TABLE IF EXISTS "sightingdb_orgs";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "sightingdb_orgs" (
  "id" int NOT NULL AUTO_INCREMENT,
  "sightingdb_id" int NOT NULL,
  "org_id" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "sightingdb_id" ("sightingdb_id"),
  KEY "org_id" ("org_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "sightingdb_orgs"
--

LOCK TABLES "sightingdb_orgs" WRITE;
/*!40000 ALTER TABLE "sightingdb_orgs" DISABLE KEYS */;
/*!40000 ALTER TABLE "sightingdb_orgs" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "sightingdbs"
--

DROP TABLE IF EXISTS "sightingdbs";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "sightingdbs" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) NOT NULL,
  "description" text,
  "owner" varchar(255) DEFAULT '',
  "host" varchar(255) DEFAULT 'http://localhost',
  "port" int DEFAULT '9999',
  "timestamp" int NOT NULL DEFAULT '0',
  "enabled" tinyint(1) NOT NULL DEFAULT '0',
  "skip_proxy" tinyint(1) NOT NULL DEFAULT '0',
  "ssl_skip_verification" tinyint(1) NOT NULL DEFAULT '0',
  "namespace" varchar(255) DEFAULT '',
  PRIMARY KEY ("id"),
  KEY "name" ("name"),
  KEY "owner" ("owner"),
  KEY "host" ("host"),
  KEY "port" ("port")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "sightingdbs"
--

LOCK TABLES "sightingdbs" WRITE;
/*!40000 ALTER TABLE "sightingdbs" DISABLE KEYS */;
/*!40000 ALTER TABLE "sightingdbs" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "sightings"
--

DROP TABLE IF EXISTS "sightings";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "sightings" (
  "id" int NOT NULL AUTO_INCREMENT,
  "attribute_id" int NOT NULL,
  "event_id" int NOT NULL,
  "org_id" int NOT NULL,
  "date_sighting" bigint NOT NULL,
  "uuid" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT '',
  "source" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT '',
  "type" int DEFAULT '0',
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  KEY "attribute_id" ("attribute_id"),
  KEY "event_id" ("event_id"),
  KEY "org_id" ("org_id"),
  KEY "source" ("source"),
  KEY "type" ("type")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "sightings"
--

LOCK TABLES "sightings" WRITE;
/*!40000 ALTER TABLE "sightings" DISABLE KEYS */;
/*!40000 ALTER TABLE "sightings" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "system_settings"
--

DROP TABLE IF EXISTS "system_settings";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "system_settings" (
  "setting" varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  "value" blob NOT NULL,
  PRIMARY KEY ("setting")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "system_settings"
--

LOCK TABLES "system_settings" WRITE;
/*!40000 ALTER TABLE "system_settings" DISABLE KEYS */;
/*!40000 ALTER TABLE "system_settings" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "tag_collection_tags"
--

DROP TABLE IF EXISTS "tag_collection_tags";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "tag_collection_tags" (
  "id" int NOT NULL AUTO_INCREMENT,
  "tag_collection_id" int NOT NULL,
  "tag_id" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "tag_collection_id" ("tag_collection_id"),
  KEY "tag_id" ("tag_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "tag_collection_tags"
--

LOCK TABLES "tag_collection_tags" WRITE;
/*!40000 ALTER TABLE "tag_collection_tags" DISABLE KEYS */;
/*!40000 ALTER TABLE "tag_collection_tags" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "tag_collections"
--

DROP TABLE IF EXISTS "tag_collections";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "tag_collections" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "user_id" int NOT NULL,
  "org_id" int NOT NULL,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "all_orgs" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  UNIQUE KEY "uuid" ("uuid"),
  KEY "user_id" ("user_id"),
  KEY "org_id" ("org_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "tag_collections"
--

LOCK TABLES "tag_collections" WRITE;
/*!40000 ALTER TABLE "tag_collections" DISABLE KEYS */;
/*!40000 ALTER TABLE "tag_collections" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "tags"
--

DROP TABLE IF EXISTS "tags";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "tags" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "colour" varchar(7) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "exportable" tinyint(1) NOT NULL,
  "org_id" int NOT NULL DEFAULT '0',
  "user_id" int NOT NULL DEFAULT '0',
  "hide_tag" tinyint(1) NOT NULL DEFAULT '0',
  "numerical_value" int DEFAULT NULL,
  "is_galaxy" tinyint(1) NOT NULL DEFAULT '0',
  "is_custom_galaxy" tinyint(1) NOT NULL DEFAULT '0',
  "local_only" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  UNIQUE KEY "name" ("name"),
  KEY "org_id" ("org_id"),
  KEY "user_id" ("user_id"),
  KEY "numerical_value" ("numerical_value")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "tags"
--

LOCK TABLES "tags" WRITE;
/*!40000 ALTER TABLE "tags" DISABLE KEYS */;
/*!40000 ALTER TABLE "tags" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "tasks"
--

DROP TABLE IF EXISTS "tasks";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "tasks" (
  "id" int NOT NULL AUTO_INCREMENT,
  "type" varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "timer" int NOT NULL,
  "scheduled_time" varchar(8) NOT NULL DEFAULT '6:00',
  "process_id" varchar(32) DEFAULT NULL,
  "description" varchar(255) NOT NULL,
  "next_execution_time" int NOT NULL,
  "message" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "tasks"
--

LOCK TABLES "tasks" WRITE;
/*!40000 ALTER TABLE "tasks" DISABLE KEYS */;
/*!40000 ALTER TABLE "tasks" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "taxii_servers"
--

DROP TABLE IF EXISTS "taxii_servers";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "taxii_servers" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "name" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "owner" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "baseurl" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "api_root" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  "description" text COLLATE utf8mb4_unicode_ci,
  "filters" text COLLATE utf8mb4_unicode_ci,
  "api_key" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id"),
  KEY "uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "baseurl" ("baseurl")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "taxii_servers"
--

LOCK TABLES "taxii_servers" WRITE;
/*!40000 ALTER TABLE "taxii_servers" DISABLE KEYS */;
/*!40000 ALTER TABLE "taxii_servers" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "taxonomies"
--

DROP TABLE IF EXISTS "taxonomies";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "taxonomies" (
  "id" int NOT NULL AUTO_INCREMENT,
  "namespace" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "version" int NOT NULL,
  "enabled" tinyint(1) NOT NULL DEFAULT '0',
  "exclusive" tinyint(1) DEFAULT '0',
  "required" tinyint(1) NOT NULL DEFAULT '0',
  "highlighted" tinyint(1) DEFAULT '0',
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "taxonomies"
--

LOCK TABLES "taxonomies" WRITE;
/*!40000 ALTER TABLE "taxonomies" DISABLE KEYS */;
/*!40000 ALTER TABLE "taxonomies" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "taxonomy_entries"
--

DROP TABLE IF EXISTS "taxonomy_entries";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "taxonomy_entries" (
  "id" int NOT NULL AUTO_INCREMENT,
  "taxonomy_predicate_id" int NOT NULL,
  "value" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "expanded" text CHARACTER SET utf8 COLLATE utf8_bin,
  "colour" varchar(7) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_bin,
  "numerical_value" int DEFAULT NULL,
  PRIMARY KEY ("id"),
  KEY "taxonomy_predicate_id" ("taxonomy_predicate_id"),
  KEY "numerical_value" ("numerical_value")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "taxonomy_entries"
--

LOCK TABLES "taxonomy_entries" WRITE;
/*!40000 ALTER TABLE "taxonomy_entries" DISABLE KEYS */;
/*!40000 ALTER TABLE "taxonomy_entries" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "taxonomy_predicates"
--

DROP TABLE IF EXISTS "taxonomy_predicates";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "taxonomy_predicates" (
  "id" int NOT NULL AUTO_INCREMENT,
  "taxonomy_id" int NOT NULL,
  "value" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "expanded" text CHARACTER SET utf8 COLLATE utf8_bin,
  "colour" varchar(7) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_bin,
  "exclusive" tinyint(1) DEFAULT '0',
  "numerical_value" int DEFAULT NULL,
  PRIMARY KEY ("id"),
  KEY "taxonomy_id" ("taxonomy_id"),
  KEY "numerical_value" ("numerical_value")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "taxonomy_predicates"
--

LOCK TABLES "taxonomy_predicates" WRITE;
/*!40000 ALTER TABLE "taxonomy_predicates" DISABLE KEYS */;
/*!40000 ALTER TABLE "taxonomy_predicates" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "template_element_attributes"
--

DROP TABLE IF EXISTS "template_element_attributes";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "template_element_attributes" (
  "id" int NOT NULL AUTO_INCREMENT,
  "template_element_id" int NOT NULL,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "to_ids" tinyint(1) NOT NULL DEFAULT '1',
  "category" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "complex" tinyint(1) NOT NULL,
  "type" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "mandatory" tinyint(1) NOT NULL,
  "batch" tinyint(1) NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "template_element_attributes"
--

LOCK TABLES "template_element_attributes" WRITE;
/*!40000 ALTER TABLE "template_element_attributes" DISABLE KEYS */;
INSERT INTO "template_element_attributes" VALUES (1,1,'From address','The source address from which the e-mail was sent.',1,'Payload delivery',0,'email-src',1,1),(2,2,'Malicious url','The malicious url in the e-mail body.',1,'Payload delivery',0,'url',1,1),(3,4,'E-mail subject','The subject line of the e-mail.',0,'Payload delivery',0,'email-subject',1,0),(4,6,'Spoofed source address','If an e-mail address was spoofed, specify which.',1,'Payload delivery',0,'email-src',0,0),(5,7,'Source IP','The source IP from which the e-mail was sent',1,'Payload delivery',0,'ip-src',0,1),(6,8,'X-mailer header','It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.',1,'Payload delivery',0,'text',0,1),(7,12,'From address','The source address from which the e-mail was sent',1,'Payload delivery',0,'email-src',1,1),(8,15,'Spoofed From Address','The spoofed source address from which the e-mail appears to be sent.',1,'Payload delivery',0,'email-src',0,1),(9,17,'E-mail Source IP','The IP address from which the e-mail was sent.',1,'Payload delivery',0,'ip-src',0,1),(10,18,'X-mailer header','It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.',1,'Payload delivery',0,'text',0,0),(11,19,'Malicious URL in the e-mail','If there was a malicious URL (or several), please specify it here',1,'Payload delivery',0,'ip-dst',0,1),(12,20,'Exploited vulnerablity','The vulnerabilities exploited during the payload delivery.',0,'Payload delivery',0,'vulnerability',0,1),(13,22,'C2 information','Command and Control information detected during the analysis.',1,'Network activity',1,'CnC',0,1),(14,23,'Artifacts dropped (File)','Any information about the files dropped during the analysis',1,'Artifacts dropped',1,'File',0,1),(15,24,'Artifacts dropped (Registry key)','Any registry keys touched during the analysis',1,'Artifacts dropped',0,'regkey',0,1),(16,25,'Artifacts dropped (Registry key + value)','Any registry keys created or altered together with the value.',1,'Artifacts dropped',0,'regkey|value',0,1),(17,26,'Persistance mechanism (filename)','Filenames (or filenames with filepaths) used as a persistence mechanism',1,'Persistence mechanism',0,'regkey|value',0,1),(18,27,'Persistence mechanism (Registry key)','Any registry keys touched as part of the persistence mechanism during the analysis ',1,'Persistence mechanism',0,'regkey',0,1),(19,28,'Persistence mechanism (Registry key + value)','Any registry keys created or modified together with their values used by the persistence mechanism',1,'Persistence mechanism',0,'regkey|value',0,1),(20,34,'C2 Information','You can drop any urls, domains, hostnames or IP addresses that were detected as the Command and Control during the analysis here. ',1,'Network activity',1,'CnC',0,1),(21,35,'Other Network Activity','Drop any applicable information about other network activity here. The attributes created here will NOT be marked for IDS exports.',0,'Network activity',1,'CnC',0,1),(22,36,'Vulnerability','The vulnerability or vulnerabilities that the sample exploits',0,'Payload delivery',0,'vulnerability',0,1),(23,37,'Artifacts Dropped (File)','Insert any data you have on dropped files here.',1,'Artifacts dropped',1,'File',0,1),(24,38,'Artifacts dropped (Registry key)','Any registry keys touched during the analysis',1,'Artifacts dropped',0,'regkey',0,1),(25,39,'Artifacts dropped (Registry key + value)','Any registry keys created or altered together with the value.',1,'Artifacts dropped',0,'regkey|value',0,1),(26,42,'Persistence mechanism (filename)','Insert any filenames used by the persistence mechanism.',1,'Persistence mechanism',0,'filename',0,1),(27,43,'Persistence Mechanism (Registry key)','Paste any registry keys that were created or modified as part of the persistence mechanism',1,'Persistence mechanism',0,'regkey',0,1),(28,44,'Persistence Mechanism (Registry key and value)','Paste any registry keys together with the values contained within created or modified by the persistence mechanism',1,'Persistence mechanism',0,'regkey|value',0,1),(29,46,'Network Indicators','Paste any combination of IP addresses, hostnames, domains or URL',1,'Network activity',1,'CnC',0,1),(30,47,'File Indicators','Paste any file hashes that you have (MD5, SHA1, SHA256) or filenames below. You can also add filename and hash pairs by using the following syntax for each applicable column: filename|hash ',1,'Payload installation',1,'File',0,1);
/*!40000 ALTER TABLE "template_element_attributes" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "template_element_files"
--

DROP TABLE IF EXISTS "template_element_files";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "template_element_files" (
  "id" int NOT NULL AUTO_INCREMENT,
  "template_element_id" int NOT NULL,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "description" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "category" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "malware" tinyint(1) NOT NULL,
  "mandatory" tinyint(1) NOT NULL,
  "batch" tinyint(1) NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "template_element_files"
--

LOCK TABLES "template_element_files" WRITE;
/*!40000 ALTER TABLE "template_element_files" DISABLE KEYS */;
INSERT INTO "template_element_files" VALUES (1,14,'Malicious Attachment','The file (or files) that was (were) attached to the e-mail itself.','Payload delivery',1,0,1),(2,21,'Payload installation','Payload installation detected during the analysis','Payload installation',1,0,1),(3,30,'Malware sample','The sample that the report is based on','Payload delivery',1,0,0),(4,40,'Artifacts dropped (Sample)','Upload any files that were dropped during the analysis.','Artifacts dropped',1,0,1);
/*!40000 ALTER TABLE "template_element_files" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "template_element_texts"
--

DROP TABLE IF EXISTS "template_element_texts";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "template_element_texts" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "template_element_id" int NOT NULL,
  "text" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "template_element_texts"
--

LOCK TABLES "template_element_texts" WRITE;
/*!40000 ALTER TABLE "template_element_texts" DISABLE KEYS */;
INSERT INTO "template_element_texts" VALUES (1,'Required fields',3,'The fields below are mandatory.'),(2,'Optional information',5,'All of the fields below are optional, please fill out anything that\'s applicable.'),(4,'Required Fields',11,'The following fields are mandatory'),(5,'Optional information about the payload delivery',13,'All of the fields below are optional, please fill out anything that\'s applicable. This section describes the payload delivery, including the e-mail itself, the attached file, the vulnerability it is exploiting and any malicious urls in the e-mail.'),(6,'Optional information obtained from analysing the malicious file',16,'Information about the analysis of the malware (if applicable). This can include C2 information, artifacts dropped during the analysis, persistance mechanism, etc.'),(7,'Malware Sample',29,'If you can, please upload the sample that the report revolves around.'),(8,'Dropped Artifacts',31,'Describe any dropped artifacts that you have encountered during your analysis'),(9,'C2 Information',32,'The following field deals with Command and Control information obtained during the analysis. All fields are optional.'),(10,'Other Network Activity',33,'If any other Network activity (such as an internet connection test) was detected during the analysis, please specify it using the following fields'),(11,'Persistence mechanism',41,'The following fields allow you to describe the persistence mechanism used by the malware'),(12,'Indicators',45,'Just paste your list of indicators based on type into the appropriate field. All of the fields are optional, so inputting a list of IP addresses into the Network indicator field for example is sufficient to complete this template.');
/*!40000 ALTER TABLE "template_element_texts" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "template_elements"
--

DROP TABLE IF EXISTS "template_elements";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "template_elements" (
  "id" int NOT NULL AUTO_INCREMENT,
  "template_id" int NOT NULL,
  "position" int NOT NULL,
  "element_definition" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "template_elements"
--

LOCK TABLES "template_elements" WRITE;
/*!40000 ALTER TABLE "template_elements" DISABLE KEYS */;
INSERT INTO "template_elements" VALUES (1,1,2,'attribute'),(2,1,3,'attribute'),(3,1,1,'text'),(4,1,4,'attribute'),(5,1,5,'text'),(6,1,6,'attribute'),(7,1,7,'attribute'),(8,1,8,'attribute'),(11,2,1,'text'),(12,2,2,'attribute'),(13,2,3,'text'),(14,2,4,'file'),(15,2,5,'attribute'),(16,2,10,'text'),(17,2,6,'attribute'),(18,2,7,'attribute'),(19,2,8,'attribute'),(20,2,9,'attribute'),(21,2,11,'file'),(22,2,12,'attribute'),(23,2,13,'attribute'),(24,2,14,'attribute'),(25,2,15,'attribute'),(26,2,16,'attribute'),(27,2,17,'attribute'),(28,2,18,'attribute'),(29,3,1,'text'),(30,3,2,'file'),(31,3,4,'text'),(32,3,9,'text'),(33,3,11,'text'),(34,3,10,'attribute'),(35,3,12,'attribute'),(36,3,3,'attribute'),(37,3,5,'attribute'),(38,3,6,'attribute'),(39,3,7,'attribute'),(40,3,8,'file'),(41,3,13,'text'),(42,3,14,'attribute'),(43,3,15,'attribute'),(44,3,16,'attribute'),(45,4,1,'text'),(46,4,2,'attribute'),(47,4,3,'attribute');
/*!40000 ALTER TABLE "template_elements" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "template_tags"
--

DROP TABLE IF EXISTS "template_tags";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "template_tags" (
  "id" int NOT NULL AUTO_INCREMENT,
  "template_id" int NOT NULL,
  "tag_id" int NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "template_tags"
--

LOCK TABLES "template_tags" WRITE;
/*!40000 ALTER TABLE "template_tags" DISABLE KEYS */;
/*!40000 ALTER TABLE "template_tags" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "templates"
--

DROP TABLE IF EXISTS "templates";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "templates" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "description" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "org" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "share" tinyint(1) NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "templates"
--

LOCK TABLES "templates" WRITE;
/*!40000 ALTER TABLE "templates" DISABLE KEYS */;
INSERT INTO "templates" VALUES (1,'Phishing E-mail','Create a MISP event about a Phishing E-mail.','MISP',1),(2,'Phishing E-mail with malicious attachment','A MISP event based on Spear-phishing containing a malicious attachment. This event can include anything from the description of the e-mail itself, the malicious attachment and its description as well as the results of the analysis done on the malicious f','MISP',1),(3,'Malware Report','This is a template for a generic malware report. ','MISP',1),(4,'Indicator List','A simple template for indicator lists.','MISP',1);
/*!40000 ALTER TABLE "templates" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "threads"
--

DROP TABLE IF EXISTS "threads";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "threads" (
  "id" int NOT NULL AUTO_INCREMENT,
  "date_created" datetime NOT NULL,
  "date_modified" datetime NOT NULL,
  "distribution" tinyint NOT NULL,
  "user_id" int NOT NULL,
  "post_count" int NOT NULL,
  "event_id" int NOT NULL,
  "title" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "org_id" int NOT NULL,
  "sharing_group_id" int NOT NULL,
  PRIMARY KEY ("id"),
  KEY "user_id" ("user_id"),
  KEY "event_id" ("event_id"),
  KEY "org_id" ("org_id"),
  KEY "sharing_group_id" ("sharing_group_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "threads"
--

LOCK TABLES "threads" WRITE;
/*!40000 ALTER TABLE "threads" DISABLE KEYS */;
/*!40000 ALTER TABLE "threads" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "threat_levels"
--

DROP TABLE IF EXISTS "threat_levels";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "threat_levels" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(50) NOT NULL,
  "description" varchar(255) DEFAULT NULL,
  "form_description" varchar(255) NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "threat_levels"
--

LOCK TABLES "threat_levels" WRITE;
/*!40000 ALTER TABLE "threat_levels" DISABLE KEYS */;
INSERT INTO "threat_levels" VALUES (1,'High','*high* means sophisticated APT malware or 0-day attack','Sophisticated APT malware or 0-day attack'),(2,'Medium','*medium* means APT malware','APT malware'),(3,'Low','*low* means mass-malware','Mass-malware'),(4,'Undefined','*undefined* no risk','No risk');
/*!40000 ALTER TABLE "threat_levels" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "user_settings"
--

DROP TABLE IF EXISTS "user_settings";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "user_settings" (
  "id" int NOT NULL AUTO_INCREMENT,
  "setting" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "value" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "user_id" int NOT NULL,
  "timestamp" int NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "unique_setting" ("user_id","setting"),
  KEY "setting" ("setting"),
  KEY "user_id" ("user_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "user_settings"
--

LOCK TABLES "user_settings" WRITE;
/*!40000 ALTER TABLE "user_settings" DISABLE KEYS */;
/*!40000 ALTER TABLE "user_settings" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "users"
--

DROP TABLE IF EXISTS "users";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "users" (
  "id" int NOT NULL AUTO_INCREMENT,
  "password" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "org_id" int NOT NULL,
  "server_id" int NOT NULL DEFAULT '0',
  "email" varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "autoalert" tinyint(1) NOT NULL DEFAULT '0',
  "authkey" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  "invited_by" int NOT NULL DEFAULT '0',
  "gpgkey" longtext CHARACTER SET utf8 COLLATE utf8_bin,
  "certif_public" longtext CHARACTER SET utf8 COLLATE utf8_bin,
  "nids_sid" int NOT NULL DEFAULT '0',
  "termsaccepted" tinyint(1) NOT NULL DEFAULT '0',
  "newsread" int unsigned DEFAULT '0',
  "role_id" int NOT NULL DEFAULT '0',
  "change_pw" tinyint(1) NOT NULL DEFAULT '0',
  "contactalert" tinyint(1) NOT NULL DEFAULT '0',
  "disabled" tinyint(1) NOT NULL DEFAULT '0',
  "expiration" datetime DEFAULT NULL,
  "current_login" int DEFAULT '0',
  "last_login" int DEFAULT '0',
  "force_logout" tinyint(1) NOT NULL DEFAULT '0',
  "date_created" bigint DEFAULT NULL,
  "date_modified" bigint DEFAULT NULL,
  "sub" varchar(255) COLLATE utf8_bin DEFAULT NULL,
  "external_auth_required" tinyint(1) NOT NULL DEFAULT '0',
  "external_auth_key" text CHARACTER SET utf8 COLLATE utf8_bin,
  "last_api_access" int DEFAULT '0',
  "notification_daily" tinyint(1) NOT NULL DEFAULT '0',
  "notification_weekly" tinyint(1) NOT NULL DEFAULT '0',
  "notification_monthly" tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY ("id"),
  UNIQUE KEY "email" ("email"),
  UNIQUE KEY "sub" ("sub"),
  KEY "org_id" ("org_id"),
  KEY "server_id" ("server_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table "warninglist_entries"
--

DROP TABLE IF EXISTS "warninglist_entries";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "warninglist_entries" (
  "id" int NOT NULL AUTO_INCREMENT,
  "value" text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  "warninglist_id" int NOT NULL,
  "comment" text,
  PRIMARY KEY ("id"),
  KEY "warninglist_id" ("warninglist_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "warninglist_entries"
--

LOCK TABLES "warninglist_entries" WRITE;
/*!40000 ALTER TABLE "warninglist_entries" DISABLE KEYS */;
/*!40000 ALTER TABLE "warninglist_entries" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "warninglist_types"
--

DROP TABLE IF EXISTS "warninglist_types";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "warninglist_types" (
  "id" int NOT NULL AUTO_INCREMENT,
  "type" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "warninglist_id" int NOT NULL,
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "warninglist_types"
--

LOCK TABLES "warninglist_types" WRITE;
/*!40000 ALTER TABLE "warninglist_types" DISABLE KEYS */;
/*!40000 ALTER TABLE "warninglist_types" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "warninglists"
--

DROP TABLE IF EXISTS "warninglists";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "warninglists" (
  "id" int NOT NULL AUTO_INCREMENT,
  "name" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "type" varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT 'string',
  "description" text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "version" int NOT NULL DEFAULT '1',
  "enabled" tinyint(1) NOT NULL DEFAULT '0',
  "default" tinyint(1) NOT NULL DEFAULT '1',
  "category" varchar(20) NOT NULL DEFAULT 'false_positive',
  PRIMARY KEY ("id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "warninglists"
--

LOCK TABLES "warninglists" WRITE;
/*!40000 ALTER TABLE "warninglists" DISABLE KEYS */;
/*!40000 ALTER TABLE "warninglists" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "workflow_blueprints"
--

DROP TABLE IF EXISTS "workflow_blueprints";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "workflow_blueprints" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "name" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "description" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "default" tinyint(1) NOT NULL DEFAULT '0',
  "data" text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY ("id"),
  KEY "uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "timestamp" ("timestamp")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "workflow_blueprints"
--

LOCK TABLES "workflow_blueprints" WRITE;
/*!40000 ALTER TABLE "workflow_blueprints" DISABLE KEYS */;
/*!40000 ALTER TABLE "workflow_blueprints" ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table "workflows"
--

DROP TABLE IF EXISTS "workflows";
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE "workflows" (
  "id" int NOT NULL AUTO_INCREMENT,
  "uuid" varchar(40) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "name" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "description" varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  "timestamp" int NOT NULL DEFAULT '0',
  "enabled" tinyint(1) NOT NULL DEFAULT '0',
  "counter" int NOT NULL DEFAULT '0',
  "trigger_id" varchar(191) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  "debug_enabled" tinyint(1) NOT NULL DEFAULT '0',
  "data" text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY ("id"),
  KEY "uuid" ("uuid"),
  KEY "name" ("name"),
  KEY "timestamp" ("timestamp"),
  KEY "trigger_id" ("trigger_id")
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table "workflows"
--

LOCK TABLES "workflows" WRITE;
/*!40000 ALTER TABLE "workflows" DISABLE KEYS */;
/*!40000 ALTER TABLE "workflows" ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-04-05 11:22:13
