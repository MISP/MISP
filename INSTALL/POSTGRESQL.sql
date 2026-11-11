-- MISP PostgreSQL install baseline, equivalent to db_version 159.
--
-- Generated with `Console/cake Admin dumpInstallBaseline` from a reference
-- database; regenerate it the same way rather than editing the DDL by
-- hand. The seed block after the DDL is what a fresh instance starts
-- with; the upgrade system carries it the rest of the way.

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
BEGIN;

CREATE TABLE "access_logs" (
    "id" serial NOT NULL,
    "created" timestamp NOT NULL,
    "user_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "authkey_id" integer DEFAULT NULL,
    "ip" bytea DEFAULT NULL,
    "request_method" smallint NOT NULL,
    "user_agent" varchar(255) DEFAULT NULL,
    "request_id" varchar(255) DEFAULT NULL,
    "controller" varchar(20) NOT NULL,
    "action" varchar(191) NOT NULL,
    "url" varchar(255) NOT NULL,
    "request" bytea DEFAULT NULL,
    "response_code" smallint NOT NULL,
    "memory_usage" integer NOT NULL,
    "duration" integer NOT NULL,
    "query_count" integer NOT NULL,
    "query_log" bytea DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_access_logs_user_id" ON "access_logs" ("user_id");

CREATE TABLE "admin_settings" (
    "id" serial NOT NULL,
    "setting" varchar(255) NOT NULL,
    "value" text NOT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_admin_settings_setting" ON "admin_settings" ("setting");

CREATE TABLE "allowedlist" (
    "id" serial NOT NULL,
    "name" text NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "analyst_data_blocklists" (
    "id" serial NOT NULL,
    "analyst_data_uuid" varchar(40) NOT NULL,
    "created" timestamp NOT NULL,
    "analyst_data_info" text NOT NULL,
    "comment" text DEFAULT NULL,
    "analyst_data_orgc" varchar(255) NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_analyst_data_blocklists_analyst_data_orgc" ON "analyst_data_blocklists" ("analyst_data_orgc");
CREATE INDEX "idx_analyst_data_blocklists_analyst_data_uuid" ON "analyst_data_blocklists" ("analyst_data_uuid");

CREATE TABLE "attachment_scans" (
    "id" serial NOT NULL,
    "type" varchar(40) NOT NULL,
    "attribute_id" integer NOT NULL,
    "infected" boolean NOT NULL,
    "malware_name" varchar(191) DEFAULT NULL,
    "timestamp" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_attachment_scans_index" ON "attachment_scans" ("type", "attribute_id");

CREATE TABLE "attributes" (
    "id" serial NOT NULL,
    "event_id" integer NOT NULL,
    "object_id" integer DEFAULT 0 NOT NULL,
    "object_relation" varchar(255) DEFAULT NULL,
    "category" varchar(255) NOT NULL,
    "type" varchar(100) NOT NULL,
    "value1" text NOT NULL,
    "value2" text NOT NULL,
    "to_ids" boolean DEFAULT 'TRUE' NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "distribution" smallint DEFAULT 0 NOT NULL,
    "sharing_group_id" integer NOT NULL,
    "comment" text DEFAULT NULL,
    "deleted" boolean DEFAULT 'FALSE' NOT NULL,
    "disable_correlation" boolean DEFAULT 'FALSE' NOT NULL,
    "first_seen" bigint DEFAULT NULL,
    "last_seen" bigint DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_attributes_category" ON "attributes" ("category");
CREATE INDEX "idx_attributes_event_id" ON "attributes" ("event_id");
CREATE INDEX "idx_attributes_first_seen" ON "attributes" ("first_seen");
CREATE INDEX "idx_attributes_last_seen" ON "attributes" ("last_seen");
CREATE INDEX "idx_attributes_object_id" ON "attributes" ("object_id");
CREATE INDEX "idx_attributes_object_relation" ON "attributes" ("object_relation");
CREATE INDEX "idx_attributes_sharing_group_id" ON "attributes" ("sharing_group_id");
CREATE INDEX "idx_attributes_timestamp" ON "attributes" ("timestamp");
CREATE INDEX "idx_attributes_type" ON "attributes" ("type");
CREATE UNIQUE INDEX "idx_attributes_uuid" ON "attributes" ("uuid");
CREATE INDEX "idx_attributes_value1" ON "attributes" USING hash ("value1");
CREATE INDEX "idx_attributes_value2" ON "attributes" USING hash ("value2");

CREATE TABLE "attribute_tags" (
    "id" serial NOT NULL,
    "attribute_id" integer NOT NULL,
    "event_id" integer NOT NULL,
    "tag_id" integer NOT NULL,
    "local" boolean DEFAULT 'FALSE' NOT NULL,
    "relationship_type" varchar(191) DEFAULT '',
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_attribute_tags_attribute_id" ON "attribute_tags" ("attribute_id");
CREATE INDEX "idx_attribute_tags_event_id" ON "attribute_tags" ("event_id");
CREATE INDEX "idx_attribute_tags_tag_id" ON "attribute_tags" ("tag_id");

CREATE TABLE "attr_value_counts" (
    "id" serial NOT NULL,
    "value" varchar(64) NOT NULL,
    "cnt_v1" bigint DEFAULT 0 NOT NULL,
    "cnt_v2" bigint DEFAULT 0 NOT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_attr_value_counts_value" ON "attr_value_counts" ("value");

CREATE TABLE "audit_logs" (
    "id" serial NOT NULL,
    "created" timestamp NOT NULL,
    "user_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "authkey_id" integer DEFAULT NULL,
    "ip" bytea DEFAULT NULL,
    "request_type" smallint NOT NULL,
    "request_id" varchar(255) DEFAULT NULL,
    "action" varchar(20) NOT NULL,
    "model" varchar(80) NOT NULL,
    "model_id" integer NOT NULL,
    "model_title" text DEFAULT NULL,
    "event_id" integer DEFAULT NULL,
    "change" bytea DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_audit_logs_event_id" ON "audit_logs" ("event_id");
CREATE INDEX "idx_audit_logs_model_id" ON "audit_logs" ("model_id");

CREATE TABLE "auth_keys" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "authkey" varchar(72) NOT NULL,
    "authkey_start" varchar(4) NOT NULL,
    "authkey_end" varchar(4) NOT NULL,
    "created" integer NOT NULL,
    "expiration" integer NOT NULL,
    "read_only" boolean DEFAULT 'FALSE' NOT NULL,
    "user_id" integer NOT NULL,
    "comment" text DEFAULT NULL,
    "allowed_ips" text DEFAULT NULL,
    "unique_ips" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_auth_keys_authkey_end" ON "auth_keys" ("authkey_end");
CREATE INDEX "idx_auth_keys_authkey_start" ON "auth_keys" ("authkey_start");
CREATE INDEX "idx_auth_keys_created" ON "auth_keys" ("created");
CREATE INDEX "idx_auth_keys_expiration" ON "auth_keys" ("expiration");
CREATE INDEX "idx_auth_keys_user_id" ON "auth_keys" ("user_id");

CREATE TABLE "bookmarks" (
    "id" serial NOT NULL,
    "user_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "name" varchar(191) NOT NULL,
    "url" text NOT NULL,
    "exposed_to_org" boolean DEFAULT 'FALSE' NOT NULL,
    "comment" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_bookmarks_name" ON "bookmarks" ("name");
CREATE INDEX "idx_bookmarks_org_id" ON "bookmarks" ("org_id");
CREATE INDEX "idx_bookmarks_user_id" ON "bookmarks" ("user_id");

CREATE TABLE "bruteforces" (
    "id" serial NOT NULL,
    "ip" varchar(255) NOT NULL,
    "username" varchar(255) NOT NULL,
    "expire" timestamp NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "cake_sessions" (
    "id" varchar(255) NOT NULL,
    "data" text NOT NULL,
    "expires" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_cake_sessions_expires" ON "cake_sessions" ("expires");

CREATE TABLE "cerebrates" (
    "id" serial NOT NULL,
    "name" varchar(191) NOT NULL,
    "url" varchar(255) NOT NULL,
    "authkey" bytea NOT NULL,
    "open" boolean DEFAULT 'FALSE',
    "org_id" integer NOT NULL,
    "pull_orgs" boolean DEFAULT 'FALSE',
    "pull_sharing_groups" boolean DEFAULT 'FALSE',
    "self_signed" boolean DEFAULT 'FALSE',
    "cert_file" varchar(255) DEFAULT NULL,
    "client_cert_file" varchar(255) DEFAULT NULL,
    "internal" boolean DEFAULT 'FALSE' NOT NULL,
    "skip_proxy" boolean DEFAULT 'FALSE' NOT NULL,
    "description" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_cerebrates_org_id" ON "cerebrates" ("org_id");
CREATE INDEX "idx_cerebrates_url" ON "cerebrates" ("url");

CREATE TABLE "collections" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "org_id" integer NOT NULL,
    "orgc_id" integer NOT NULL,
    "user_id" integer NOT NULL,
    "created" timestamp NOT NULL,
    "modified" timestamp NOT NULL,
    "distribution" smallint NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "name" varchar(191) NOT NULL,
    "type" varchar(80) NOT NULL,
    "description" text DEFAULT NULL,
    "locked" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_collections_distribution" ON "collections" ("distribution");
CREATE INDEX "idx_collections_name" ON "collections" ("name");
CREATE INDEX "idx_collections_org_id" ON "collections" ("org_id");
CREATE INDEX "idx_collections_orgc_id" ON "collections" ("orgc_id");
CREATE INDEX "idx_collections_sharing_group_id" ON "collections" ("sharing_group_id");
CREATE INDEX "idx_collections_type" ON "collections" ("type");
CREATE INDEX "idx_collections_user_id" ON "collections" ("user_id");
CREATE UNIQUE INDEX "idx_collections_uuid" ON "collections" ("uuid");

CREATE TABLE "collection_elements" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "element_uuid" varchar(40) NOT NULL,
    "element_type" varchar(80) NOT NULL,
    "collection_id" integer NOT NULL,
    "description" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_collection_elements_collection_id" ON "collection_elements" ("collection_id");
CREATE INDEX "idx_collection_elements_element_type" ON "collection_elements" ("element_type");
CREATE INDEX "idx_collection_elements_element_uuid" ON "collection_elements" ("element_uuid");
CREATE UNIQUE INDEX "idx_collection_elements_unique_element" ON "collection_elements" ("element_uuid", "collection_id");
CREATE UNIQUE INDEX "idx_collection_elements_uuid" ON "collection_elements" ("uuid");

CREATE TABLE "correlations" (
    "id" serial NOT NULL,
    "value" text NOT NULL,
    "1_event_id" integer NOT NULL,
    "1_attribute_id" integer NOT NULL,
    "event_id" integer NOT NULL,
    "attribute_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "distribution" smallint NOT NULL,
    "a_distribution" smallint NOT NULL,
    "sharing_group_id" integer NOT NULL,
    "a_sharing_group_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_correlations_1_attribute_id" ON "correlations" ("1_attribute_id");
CREATE INDEX "idx_correlations_1_event_id" ON "correlations" ("1_event_id");
CREATE INDEX "idx_correlations_attribute_id" ON "correlations" ("attribute_id");
CREATE INDEX "idx_correlations_event_id" ON "correlations" ("event_id");

CREATE TABLE "correlation_exclusions" (
    "id" serial NOT NULL,
    "value" text NOT NULL,
    "from_json" boolean DEFAULT 'FALSE',
    "comment" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_correlation_exclusions_value" ON "correlation_exclusions" ("value");

CREATE TABLE "correlation_rules" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "name" varchar(191) NOT NULL,
    "comment" text DEFAULT NULL,
    "selector_type" varchar(40) NOT NULL,
    "selector_list" text DEFAULT NULL,
    "created" integer NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_correlation_rules_name" ON "correlation_rules" ("name");
CREATE INDEX "idx_correlation_rules_selector_type" ON "correlation_rules" ("selector_type");
CREATE INDEX "idx_correlation_rules_uuid" ON "correlation_rules" ("uuid");
ALTER TABLE "correlation_rules" ALTER COLUMN "created" SET DEFAULT FLOOR(EXTRACT(EPOCH FROM NOW()))::integer;

CREATE TABLE "correlation_values" (
    "id" serial NOT NULL,
    "value" varchar(191) NOT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_correlation_values_value" ON "correlation_values" ("value");

CREATE TABLE "cryptographic_keys" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "type" varchar(40) NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "parent_id" integer NOT NULL,
    "parent_type" varchar(40) NOT NULL,
    "key_data" text DEFAULT NULL,
    "revoked" boolean DEFAULT 'FALSE' NOT NULL,
    "fingerprint" varchar(255) DEFAULT '' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_cryptographic_keys_fingerprint" ON "cryptographic_keys" ("fingerprint");
CREATE INDEX "idx_cryptographic_keys_parent_id" ON "cryptographic_keys" ("parent_id");
CREATE INDEX "idx_cryptographic_keys_parent_type" ON "cryptographic_keys" ("parent_type");
CREATE INDEX "idx_cryptographic_keys_type" ON "cryptographic_keys" ("type");
CREATE INDEX "idx_cryptographic_keys_uuid" ON "cryptographic_keys" ("uuid");

CREATE TABLE "dashboards" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "name" varchar(191) NOT NULL,
    "description" text DEFAULT NULL,
    "default" boolean DEFAULT 'FALSE' NOT NULL,
    "selectable" boolean DEFAULT 'FALSE' NOT NULL,
    "user_id" integer DEFAULT 0 NOT NULL,
    "restrict_to_org_id" integer DEFAULT 0 NOT NULL,
    "restrict_to_role_id" integer DEFAULT 0 NOT NULL,
    "restrict_to_permission_flag" varchar(191) DEFAULT '' NOT NULL,
    "value" text DEFAULT NULL,
    "timestamp" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_dashboards_name" ON "dashboards" ("name");
CREATE INDEX "idx_dashboards_restrict_to_org_id" ON "dashboards" ("restrict_to_org_id");
CREATE INDEX "idx_dashboards_restrict_to_permission_flag" ON "dashboards" ("restrict_to_permission_flag");
CREATE INDEX "idx_dashboards_user_id" ON "dashboards" ("user_id");
CREATE UNIQUE INDEX "idx_dashboards_uuid" ON "dashboards" ("uuid");

CREATE TABLE "decaying_models" (
    "id" serial NOT NULL,
    "uuid" varchar(40) DEFAULT NULL,
    "name" varchar(255) NOT NULL,
    "parameters" text DEFAULT NULL,
    "attribute_types" text DEFAULT NULL,
    "description" text DEFAULT NULL,
    "org_id" integer DEFAULT NULL,
    "enabled" boolean DEFAULT 'FALSE' NOT NULL,
    "all_orgs" boolean DEFAULT 'TRUE' NOT NULL,
    "ref" text DEFAULT NULL,
    "formula" varchar(255) NOT NULL,
    "version" varchar(255) DEFAULT '' NOT NULL,
    "default" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_decaying_models_all_orgs" ON "decaying_models" ("all_orgs");
CREATE INDEX "idx_decaying_models_enabled" ON "decaying_models" ("enabled");
CREATE INDEX "idx_decaying_models_name" ON "decaying_models" ("name");
CREATE INDEX "idx_decaying_models_org_id" ON "decaying_models" ("org_id");
CREATE INDEX "idx_decaying_models_uuid" ON "decaying_models" ("uuid");
CREATE INDEX "idx_decaying_models_version" ON "decaying_models" ("version");

CREATE TABLE "decaying_model_mappings" (
    "id" serial NOT NULL,
    "attribute_type" varchar(255) NOT NULL,
    "model_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_decaying_model_mappings_model_id" ON "decaying_model_mappings" ("model_id");

CREATE TABLE "default_correlations" (
    "id" serial NOT NULL,
    "attribute_id" integer NOT NULL,
    "object_id" integer NOT NULL,
    "event_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "distribution" smallint NOT NULL,
    "object_distribution" smallint NOT NULL,
    "event_distribution" smallint NOT NULL,
    "sharing_group_id" integer DEFAULT 0 NOT NULL,
    "object_sharing_group_id" integer DEFAULT 0 NOT NULL,
    "event_sharing_group_id" integer DEFAULT 0 NOT NULL,
    "1_attribute_id" integer NOT NULL,
    "1_object_id" integer NOT NULL,
    "1_event_id" integer NOT NULL,
    "1_org_id" integer NOT NULL,
    "1_distribution" smallint NOT NULL,
    "1_object_distribution" smallint NOT NULL,
    "1_event_distribution" smallint NOT NULL,
    "1_sharing_group_id" integer DEFAULT 0 NOT NULL,
    "1_object_sharing_group_id" integer DEFAULT 0 NOT NULL,
    "1_event_sharing_group_id" integer DEFAULT 0 NOT NULL,
    "value_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_default_correlations_1_attribute_id" ON "default_correlations" ("1_attribute_id");
CREATE INDEX "idx_default_correlations_1_event_id" ON "default_correlations" ("1_event_id");
CREATE INDEX "idx_default_correlations_1_object_id" ON "default_correlations" ("1_object_id");
CREATE INDEX "idx_default_correlations_attribute_id" ON "default_correlations" ("attribute_id");
CREATE INDEX "idx_default_correlations_event_id" ON "default_correlations" ("event_id");
CREATE INDEX "idx_default_correlations_object_id" ON "default_correlations" ("object_id");
CREATE UNIQUE INDEX "idx_default_correlations_unique_correlation" ON "default_correlations" ("attribute_id", "1_attribute_id", "value_id");
CREATE INDEX "idx_default_correlations_value_id" ON "default_correlations" ("value_id");

CREATE TABLE "events" (
    "id" serial NOT NULL,
    "org_id" integer NOT NULL,
    "date" date NOT NULL,
    "info" text NOT NULL,
    "user_id" integer NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "published" boolean DEFAULT 'FALSE' NOT NULL,
    "analysis" smallint NOT NULL,
    "attribute_count" integer DEFAULT 0,
    "orgc_id" integer NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "distribution" smallint DEFAULT 0 NOT NULL,
    "sharing_group_id" integer NOT NULL,
    "proposal_email_lock" boolean DEFAULT 'FALSE' NOT NULL,
    "locked" boolean DEFAULT 'FALSE' NOT NULL,
    "threat_level_id" integer NOT NULL,
    "publish_timestamp" integer DEFAULT 0 NOT NULL,
    "sighting_timestamp" integer DEFAULT 0 NOT NULL,
    "disable_correlation" boolean DEFAULT 'FALSE' NOT NULL,
    "extends_uuid" varchar(40) DEFAULT '',
    "protected" boolean DEFAULT NULL,
    "first_publication" integer DEFAULT 0 NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_events_extends_uuid" ON "events" ("extends_uuid");
CREATE INDEX "idx_events_first_publication" ON "events" ("first_publication");
CREATE INDEX "idx_events_org_id" ON "events" ("org_id");
CREATE INDEX "idx_events_orgc_id" ON "events" ("orgc_id");
CREATE INDEX "idx_events_sharing_group_id" ON "events" ("sharing_group_id");
CREATE UNIQUE INDEX "idx_events_uuid" ON "events" ("uuid");
CREATE INDEX "idx_events_info" ON "events" USING hash ("info");

CREATE TABLE "event_blocklists" (
    "id" serial NOT NULL,
    "event_uuid" varchar(40) NOT NULL,
    "created" timestamp NOT NULL,
    "event_info" text NOT NULL,
    "comment" text DEFAULT NULL,
    "event_orgc" varchar(255) NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_blocklists_event_orgc" ON "event_blocklists" ("event_orgc");
CREATE UNIQUE INDEX "idx_event_blocklists_event_uuid" ON "event_blocklists" ("event_uuid");

CREATE TABLE "event_delegations" (
    "id" serial NOT NULL,
    "org_id" integer NOT NULL,
    "requester_org_id" integer NOT NULL,
    "event_id" integer NOT NULL,
    "message" text DEFAULT NULL,
    "distribution" smallint DEFAULT -1 NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_delegations_event_id" ON "event_delegations" ("event_id");
CREATE INDEX "idx_event_delegations_org_id" ON "event_delegations" ("org_id");

CREATE TABLE "event_graph" (
    "id" serial NOT NULL,
    "event_id" integer NOT NULL,
    "user_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "network_name" varchar(255) DEFAULT NULL,
    "network_json" text NOT NULL,
    "preview_img" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_graph_event_id" ON "event_graph" ("event_id");
CREATE INDEX "idx_event_graph_org_id" ON "event_graph" ("org_id");
CREATE INDEX "idx_event_graph_timestamp" ON "event_graph" ("timestamp");
CREATE INDEX "idx_event_graph_user_id" ON "event_graph" ("user_id");

CREATE TABLE "event_locks" (
    "id" serial NOT NULL,
    "event_id" integer NOT NULL,
    "user_id" integer NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_locks_event_id" ON "event_locks" ("event_id");
CREATE INDEX "idx_event_locks_timestamp" ON "event_locks" ("timestamp");
CREATE INDEX "idx_event_locks_user_id" ON "event_locks" ("user_id");

CREATE TABLE "event_reports" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "event_id" integer NOT NULL,
    "name" varchar(255) NOT NULL,
    "content" text DEFAULT NULL,
    "distribution" smallint DEFAULT 0 NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "timestamp" integer NOT NULL,
    "deleted" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_reports_event_id" ON "event_reports" ("event_id");
CREATE INDEX "idx_event_reports_name" ON "event_reports" ("name");
CREATE UNIQUE INDEX "idx_event_reports_u_uuid" ON "event_reports" ("uuid");

CREATE TABLE "event_report_tags" (
    "id" serial NOT NULL,
    "event_report_id" integer NOT NULL,
    "tag_id" integer NOT NULL,
    "local" boolean DEFAULT 'FALSE' NOT NULL,
    "relationship_type" varchar(191) DEFAULT '',
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_report_tags_event_report_id" ON "event_report_tags" ("event_report_id");
CREATE INDEX "idx_event_report_tags_tag_id" ON "event_report_tags" ("tag_id");

CREATE TABLE "event_report_template_variables" (
    "id" serial NOT NULL,
    "name" varchar(191) NOT NULL,
    "value" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_report_template_variables_name" ON "event_report_template_variables" ("name");

CREATE TABLE "event_tags" (
    "id" serial NOT NULL,
    "event_id" integer NOT NULL,
    "tag_id" integer NOT NULL,
    "local" boolean DEFAULT 'FALSE' NOT NULL,
    "relationship_type" varchar(191) DEFAULT '',
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_tags_event_id" ON "event_tags" ("event_id");
CREATE INDEX "idx_event_tags_tag_id" ON "event_tags" ("tag_id");

CREATE TABLE "event_templates" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "name" varchar(255) NOT NULL,
    "description" text DEFAULT NULL,
    "org_id" integer NOT NULL,
    "creator_user_id" integer NOT NULL,
    "distribution" smallint DEFAULT 0 NOT NULL,
    "active" boolean DEFAULT 'TRUE' NOT NULL,
    "misp_default" boolean DEFAULT 'FALSE' NOT NULL,
    "exposed" boolean DEFAULT 'FALSE' NOT NULL,
    "version" integer DEFAULT 1 NOT NULL,
    "definition" text NOT NULL,
    "created" timestamp NOT NULL,
    "modified" timestamp NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_templates_active" ON "event_templates" ("active");
CREATE INDEX "idx_event_templates_exposed" ON "event_templates" ("exposed");
CREATE INDEX "idx_event_templates_name" ON "event_templates" ("name");
CREATE INDEX "idx_event_templates_org_id" ON "event_templates" ("org_id");
CREATE UNIQUE INDEX "idx_event_templates_uuid" ON "event_templates" ("uuid");

CREATE TABLE "event_template_object_dependencies" (
    "id" serial NOT NULL,
    "event_template_id" integer NOT NULL,
    "object_template_uuid" varchar(40) NOT NULL,
    "object_template_name" varchar(255) NOT NULL,
    "minimum_version" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_event_template_object_dependencies_event_template_id" ON "event_template_object_dependencies" ("event_template_id");
CREATE INDEX "idx_event_template_object_dependencies_object_template_uuid" ON "event_template_object_dependencies" ("object_template_uuid");

CREATE TABLE "favourite_tags" (
    "id" serial NOT NULL,
    "tag_id" integer NOT NULL,
    "user_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_favourite_tags_tag_id" ON "favourite_tags" ("tag_id");
CREATE INDEX "idx_favourite_tags_user_id" ON "favourite_tags" ("user_id");

CREATE TABLE "feeds" (
    "id" serial NOT NULL,
    "name" varchar(255) NOT NULL,
    "provider" varchar(255) NOT NULL,
    "url" varchar(255) NOT NULL,
    "rules" text DEFAULT NULL,
    "enabled" boolean DEFAULT 'FALSE',
    "distribution" smallint DEFAULT 0 NOT NULL,
    "sharing_group_id" integer DEFAULT 0 NOT NULL,
    "tag_id" integer DEFAULT 0 NOT NULL,
    "default" boolean DEFAULT 'FALSE',
    "source_format" varchar(255) DEFAULT 'misp',
    "fixed_event" boolean DEFAULT 'FALSE' NOT NULL,
    "delta_merge" boolean DEFAULT 'FALSE' NOT NULL,
    "event_id" integer DEFAULT 0 NOT NULL,
    "publish" boolean DEFAULT 'FALSE' NOT NULL,
    "override_ids" boolean DEFAULT 'FALSE' NOT NULL,
    "settings" text DEFAULT NULL,
    "input_source" varchar(255) DEFAULT 'network' NOT NULL,
    "delete_local_file" boolean DEFAULT 'FALSE',
    "lookup_visible" boolean DEFAULT 'FALSE',
    "headers" text DEFAULT NULL,
    "caching_enabled" boolean DEFAULT 'FALSE' NOT NULL,
    "force_to_ids" boolean DEFAULT 'FALSE' NOT NULL,
    "orgc_id" integer DEFAULT 0 NOT NULL,
    "tag_collection_id" integer DEFAULT 0 NOT NULL,
    "lock_events" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_feeds_input_source" ON "feeds" ("input_source");
CREATE INDEX "idx_feeds_orgc_id" ON "feeds" ("orgc_id");

CREATE TABLE "fuzzy_correlate_ssdeep" (
    "id" serial NOT NULL,
    "chunk" varchar(12) NOT NULL,
    "attribute_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_fuzzy_correlate_ssdeep_attribute_id" ON "fuzzy_correlate_ssdeep" ("attribute_id");
CREATE INDEX "idx_fuzzy_correlate_ssdeep_chunk" ON "fuzzy_correlate_ssdeep" ("chunk");

CREATE TABLE "galaxies" (
    "id" serial NOT NULL,
    "uuid" varchar(255) NOT NULL,
    "name" varchar(255) DEFAULT '' NOT NULL,
    "type" varchar(255) NOT NULL,
    "description" text NOT NULL,
    "version" varchar(255) NOT NULL,
    "icon" varchar(255) DEFAULT '' NOT NULL,
    "namespace" varchar(255) DEFAULT 'misp' NOT NULL,
    "enabled" boolean DEFAULT 'TRUE' NOT NULL,
    "local_only" boolean DEFAULT 'FALSE' NOT NULL,
    "kill_chain_order" text DEFAULT NULL,
    "default" boolean DEFAULT 'FALSE' NOT NULL,
    "org_id" integer NOT NULL,
    "orgc_id" integer NOT NULL,
    "created" timestamp NOT NULL,
    "modified" timestamp NOT NULL,
    "distribution" smallint DEFAULT 0 NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_galaxies_name" ON "galaxies" ("name");
CREATE INDEX "idx_galaxies_namespace" ON "galaxies" ("namespace");
CREATE INDEX "idx_galaxies_type" ON "galaxies" ("type");
CREATE UNIQUE INDEX "idx_galaxies_uuid" ON "galaxies" ("uuid");

CREATE TABLE "galaxy_clusters" (
    "id" serial NOT NULL,
    "uuid" varchar(255) DEFAULT '' NOT NULL,
    "collection_uuid" varchar(255) NOT NULL,
    "type" varchar(255) NOT NULL,
    "value" text NOT NULL,
    "tag_name" varchar(255) DEFAULT '' NOT NULL,
    "description" text DEFAULT NULL,
    "galaxy_id" integer NOT NULL,
    "source" varchar(255) DEFAULT '' NOT NULL,
    "authors" text NOT NULL,
    "version" integer DEFAULT 0,
    "distribution" smallint DEFAULT 0 NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "org_id" integer NOT NULL,
    "orgc_id" integer NOT NULL,
    "default" boolean DEFAULT 'FALSE' NOT NULL,
    "locked" boolean DEFAULT 'FALSE' NOT NULL,
    "extends_uuid" varchar(40) DEFAULT '',
    "extends_version" integer DEFAULT 0,
    "published" boolean DEFAULT 'FALSE' NOT NULL,
    "deleted" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_galaxy_clusters_collection_uuid" ON "galaxy_clusters" ("collection_uuid");
CREATE INDEX "idx_galaxy_clusters_default" ON "galaxy_clusters" ("default");
CREATE INDEX "idx_galaxy_clusters_extends_uuid" ON "galaxy_clusters" ("extends_uuid");
CREATE INDEX "idx_galaxy_clusters_extends_version" ON "galaxy_clusters" ("extends_version");
CREATE INDEX "idx_galaxy_clusters_galaxy_id" ON "galaxy_clusters" ("galaxy_id");
CREATE INDEX "idx_galaxy_clusters_org_id" ON "galaxy_clusters" ("org_id");
CREATE INDEX "idx_galaxy_clusters_orgc_id" ON "galaxy_clusters" ("orgc_id");
CREATE INDEX "idx_galaxy_clusters_sharing_group_id" ON "galaxy_clusters" ("sharing_group_id");
CREATE INDEX "idx_galaxy_clusters_tag_name" ON "galaxy_clusters" ("tag_name");
CREATE INDEX "idx_galaxy_clusters_type" ON "galaxy_clusters" ("type");
CREATE INDEX "idx_galaxy_clusters_uuid" ON "galaxy_clusters" ("uuid");
CREATE INDEX "idx_galaxy_clusters_version" ON "galaxy_clusters" ("version");
CREATE INDEX "idx_galaxy_clusters_value" ON "galaxy_clusters" USING hash ("value");

CREATE TABLE "galaxy_cluster_blocklists" (
    "id" serial NOT NULL,
    "cluster_uuid" varchar(40) NOT NULL,
    "created" timestamp NOT NULL,
    "cluster_info" text NOT NULL,
    "comment" text DEFAULT NULL,
    "cluster_orgc" varchar(255) NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_galaxy_cluster_blocklists_cluster_orgc" ON "galaxy_cluster_blocklists" ("cluster_orgc");
CREATE INDEX "idx_galaxy_cluster_blocklists_cluster_uuid" ON "galaxy_cluster_blocklists" ("cluster_uuid");

CREATE TABLE "galaxy_cluster_relations" (
    "id" serial NOT NULL,
    "galaxy_cluster_id" integer NOT NULL,
    "referenced_galaxy_cluster_id" integer NOT NULL,
    "referenced_galaxy_cluster_uuid" varchar(255) NOT NULL,
    "referenced_galaxy_cluster_type" text NOT NULL,
    "galaxy_cluster_uuid" varchar(40) NOT NULL,
    "distribution" smallint DEFAULT 0 NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "default" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_galaxy_cluster_relations_default" ON "galaxy_cluster_relations" ("default");
CREATE INDEX "idx_galaxy_cluster_relations_galaxy_cluster_id" ON "galaxy_cluster_relations" ("galaxy_cluster_id");
CREATE INDEX "idx_galaxy_cluster_relations_galaxy_cluster_uuid" ON "galaxy_cluster_relations" ("galaxy_cluster_uuid");
CREATE INDEX "idx_galaxy_cluster_relations_referenced_galaxy_cluster_id" ON "galaxy_cluster_relations" ("referenced_galaxy_cluster_id");
CREATE INDEX "idx_galaxy_cluster_relations_sharing_group_id" ON "galaxy_cluster_relations" ("sharing_group_id");
CREATE INDEX "idx_galaxy_cluster_relations_referenced_galaxy_cluster_type" ON "galaxy_cluster_relations" USING hash ("referenced_galaxy_cluster_type");

CREATE TABLE "galaxy_cluster_relation_tags" (
    "id" serial NOT NULL,
    "galaxy_cluster_relation_id" integer NOT NULL,
    "tag_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_galaxy_cluster_relation_tags_galaxy_cluster_relation_id" ON "galaxy_cluster_relation_tags" ("galaxy_cluster_relation_id");
CREATE INDEX "idx_galaxy_cluster_relation_tags_tag_id" ON "galaxy_cluster_relation_tags" ("tag_id");

CREATE TABLE "galaxy_elements" (
    "id" serial NOT NULL,
    "galaxy_cluster_id" integer NOT NULL,
    "key" varchar(255) DEFAULT '' NOT NULL,
    "value" text NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_galaxy_elements_galaxy_cluster_id" ON "galaxy_elements" ("galaxy_cluster_id");
CREATE INDEX "idx_galaxy_elements_key" ON "galaxy_elements" ("key");
CREATE INDEX "idx_galaxy_elements_value" ON "galaxy_elements" USING hash ("value");

CREATE TABLE "inbox" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "title" varchar(191) NOT NULL,
    "type" varchar(191) NOT NULL,
    "ip" varchar(191) NOT NULL,
    "user_agent" text DEFAULT NULL,
    "user_agent_sha256" varchar(64) NOT NULL,
    "comment" text DEFAULT NULL,
    "deleted" boolean DEFAULT 'FALSE' NOT NULL,
    "timestamp" integer NOT NULL,
    "store_as_file" boolean DEFAULT 'FALSE' NOT NULL,
    "data" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_inbox_ip" ON "inbox" ("ip");
CREATE INDEX "idx_inbox_timestamp" ON "inbox" ("timestamp");
CREATE INDEX "idx_inbox_title" ON "inbox" ("title");
CREATE INDEX "idx_inbox_type" ON "inbox" ("type");
CREATE INDEX "idx_inbox_user_agent_sha256" ON "inbox" ("user_agent_sha256");
CREATE UNIQUE INDEX "idx_inbox_uuid" ON "inbox" ("uuid");

CREATE TABLE "jobs" (
    "id" serial NOT NULL,
    "worker" varchar(32) NOT NULL,
    "job_type" varchar(32) NOT NULL,
    "job_input" text NOT NULL,
    "status" smallint DEFAULT 0 NOT NULL,
    "retries" integer DEFAULT 0 NOT NULL,
    "message" text NOT NULL,
    "progress" integer DEFAULT 0 NOT NULL,
    "org_id" integer DEFAULT 0 NOT NULL,
    "process_id" varchar(36) DEFAULT NULL,
    "date_created" timestamp NOT NULL,
    "date_modified" timestamp NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "logs" (
    "id" serial NOT NULL,
    "title" text DEFAULT NULL,
    "created" timestamp NOT NULL,
    "model" varchar(80) NOT NULL,
    "model_id" integer NOT NULL,
    "action" varchar(20) NOT NULL,
    "user_id" integer NOT NULL,
    "change" text DEFAULT NULL,
    "email" varchar(255) DEFAULT '' NOT NULL,
    "org" varchar(255) DEFAULT '' NOT NULL,
    "description" text DEFAULT NULL,
    "ip" varchar(45) DEFAULT '' NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "news" (
    "id" serial NOT NULL,
    "message" text NOT NULL,
    "title" text NOT NULL,
    "user_id" integer NOT NULL,
    "date_created" integer NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "notes" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "object_uuid" varchar(40) NOT NULL,
    "object_type" varchar(80) NOT NULL,
    "authors" text DEFAULT NULL,
    "org_uuid" varchar(40) NOT NULL,
    "orgc_uuid" varchar(40) NOT NULL,
    "created" timestamp NOT NULL,
    "modified" timestamp NOT NULL,
    "distribution" smallint NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "locked" boolean DEFAULT 'FALSE' NOT NULL,
    "note" text DEFAULT NULL,
    "language" varchar(16) DEFAULT 'en',
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_notes_distribution" ON "notes" ("distribution");
CREATE INDEX "idx_notes_object_type" ON "notes" ("object_type");
CREATE INDEX "idx_notes_object_uuid" ON "notes" ("object_uuid");
CREATE INDEX "idx_notes_org_uuid" ON "notes" ("org_uuid");
CREATE INDEX "idx_notes_orgc_uuid" ON "notes" ("orgc_uuid");
CREATE INDEX "idx_notes_sharing_group_id" ON "notes" ("sharing_group_id");
CREATE UNIQUE INDEX "idx_notes_uuid" ON "notes" ("uuid");

CREATE TABLE "noticelists" (
    "id" serial NOT NULL,
    "name" varchar(255) NOT NULL,
    "expanded_name" text NOT NULL,
    "ref" text DEFAULT NULL,
    "geographical_area" varchar(255) DEFAULT NULL,
    "version" integer DEFAULT 1 NOT NULL,
    "enabled" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_noticelists_geographical_area" ON "noticelists" ("geographical_area");
CREATE INDEX "idx_noticelists_name" ON "noticelists" ("name");

CREATE TABLE "noticelist_entries" (
    "id" serial NOT NULL,
    "noticelist_id" integer NOT NULL,
    "data" text NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_noticelist_entries_noticelist_id" ON "noticelist_entries" ("noticelist_id");

CREATE TABLE "notification_logs" (
    "id" serial NOT NULL,
    "org_id" integer NOT NULL,
    "type" varchar(255) NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_notification_logs_org_id" ON "notification_logs" ("org_id");
CREATE INDEX "idx_notification_logs_type" ON "notification_logs" ("type");

CREATE TABLE "no_acl_correlations" (
    "id" serial NOT NULL,
    "attribute_id" integer NOT NULL,
    "1_attribute_id" integer NOT NULL,
    "event_id" integer NOT NULL,
    "1_event_id" integer NOT NULL,
    "value_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_no_acl_correlations_1_attribute_id" ON "no_acl_correlations" ("1_attribute_id");
CREATE INDEX "idx_no_acl_correlations_1_event_id" ON "no_acl_correlations" ("1_event_id");
CREATE INDEX "idx_no_acl_correlations_attribute_id" ON "no_acl_correlations" ("attribute_id");
CREATE INDEX "idx_no_acl_correlations_event_id" ON "no_acl_correlations" ("event_id");
CREATE UNIQUE INDEX "idx_no_acl_correlations_unique_correlation" ON "no_acl_correlations" ("attribute_id", "1_attribute_id", "value_id");
CREATE INDEX "idx_no_acl_correlations_value_id" ON "no_acl_correlations" ("value_id");

CREATE TABLE "objects" (
    "id" serial NOT NULL,
    "name" varchar(255) DEFAULT NULL,
    "meta-category" varchar(255) DEFAULT NULL,
    "description" text DEFAULT NULL,
    "template_uuid" varchar(40) DEFAULT NULL,
    "template_version" integer NOT NULL,
    "event_id" integer NOT NULL,
    "uuid" varchar(40) DEFAULT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "distribution" smallint DEFAULT 0 NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "comment" text NOT NULL,
    "deleted" boolean DEFAULT 'FALSE' NOT NULL,
    "first_seen" bigint DEFAULT NULL,
    "last_seen" bigint DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_objects_distribution" ON "objects" ("distribution");
CREATE INDEX "idx_objects_event_id" ON "objects" ("event_id");
CREATE INDEX "idx_objects_first_seen" ON "objects" ("first_seen");
CREATE INDEX "idx_objects_last_seen" ON "objects" ("last_seen");
CREATE INDEX "idx_objects_meta-category" ON "objects" ("meta-category");
CREATE INDEX "idx_objects_name" ON "objects" ("name");
CREATE INDEX "idx_objects_sharing_group_id" ON "objects" ("sharing_group_id");
CREATE INDEX "idx_objects_template_uuid" ON "objects" ("template_uuid");
CREATE INDEX "idx_objects_template_version" ON "objects" ("template_version");
CREATE INDEX "idx_objects_timestamp" ON "objects" ("timestamp");
CREATE UNIQUE INDEX "idx_objects_uuid" ON "objects" ("uuid");

CREATE TABLE "object_references" (
    "id" serial NOT NULL,
    "uuid" varchar(40) DEFAULT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "object_id" integer NOT NULL,
    "event_id" integer NOT NULL,
    "source_uuid" varchar(40) DEFAULT NULL,
    "referenced_uuid" varchar(40) DEFAULT NULL,
    "referenced_id" integer NOT NULL,
    "referenced_type" integer DEFAULT 0 NOT NULL,
    "relationship_type" varchar(255) DEFAULT NULL,
    "comment" text NOT NULL,
    "deleted" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_object_references_event_id" ON "object_references" ("event_id");
CREATE INDEX "idx_object_references_object_id" ON "object_references" ("object_id");
CREATE INDEX "idx_object_references_referenced_id" ON "object_references" ("referenced_id");
CREATE UNIQUE INDEX "idx_object_references_uuid" ON "object_references" ("uuid");

CREATE TABLE "object_relationships" (
    "id" serial NOT NULL,
    "version" integer NOT NULL,
    "name" varchar(255) DEFAULT NULL,
    "description" text NOT NULL,
    "format" text NOT NULL,
    "highlighted" boolean DEFAULT 'FALSE',
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_object_relationships_name" ON "object_relationships" ("name");

CREATE TABLE "object_templates" (
    "id" serial NOT NULL,
    "user_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "uuid" varchar(40) DEFAULT NULL,
    "name" varchar(255) DEFAULT NULL,
    "meta-category" varchar(255) DEFAULT NULL,
    "description" text DEFAULT NULL,
    "version" integer NOT NULL,
    "requirements" text DEFAULT NULL,
    "fixed" boolean DEFAULT 'FALSE' NOT NULL,
    "active" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_object_templates_meta-category" ON "object_templates" ("meta-category");
CREATE INDEX "idx_object_templates_name" ON "object_templates" ("name");
CREATE INDEX "idx_object_templates_org_id" ON "object_templates" ("org_id");
CREATE INDEX "idx_object_templates_user_id" ON "object_templates" ("user_id");
CREATE INDEX "idx_object_templates_uuid" ON "object_templates" ("uuid");

CREATE TABLE "object_template_elements" (
    "id" serial NOT NULL,
    "object_template_id" integer NOT NULL,
    "object_relation" varchar(255) DEFAULT NULL,
    "type" varchar(255) DEFAULT NULL,
    "ui-priority" integer NOT NULL,
    "categories" text DEFAULT NULL,
    "sane_default" text DEFAULT NULL,
    "values_list" text DEFAULT NULL,
    "description" text DEFAULT NULL,
    "disable_correlation" boolean DEFAULT NULL,
    "multiple" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_object_template_elements_object_relation" ON "object_template_elements" ("object_relation");
CREATE INDEX "idx_object_template_elements_object_template_id" ON "object_template_elements" ("object_template_id");
CREATE INDEX "idx_object_template_elements_type" ON "object_template_elements" ("type");

CREATE TABLE "opinions" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "object_uuid" varchar(40) NOT NULL,
    "object_type" varchar(80) NOT NULL,
    "authors" text DEFAULT NULL,
    "org_uuid" varchar(40) NOT NULL,
    "orgc_uuid" varchar(40) NOT NULL,
    "created" timestamp NOT NULL,
    "modified" timestamp NOT NULL,
    "distribution" smallint NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "locked" boolean DEFAULT 'FALSE' NOT NULL,
    "opinion" integer DEFAULT NULL,
    "comment" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_opinions_distribution" ON "opinions" ("distribution");
CREATE INDEX "idx_opinions_object_type" ON "opinions" ("object_type");
CREATE INDEX "idx_opinions_object_uuid" ON "opinions" ("object_uuid");
CREATE INDEX "idx_opinions_opinion" ON "opinions" ("opinion");
CREATE INDEX "idx_opinions_org_uuid" ON "opinions" ("org_uuid");
CREATE INDEX "idx_opinions_orgc_uuid" ON "opinions" ("orgc_uuid");
CREATE INDEX "idx_opinions_sharing_group_id" ON "opinions" ("sharing_group_id");
CREATE UNIQUE INDEX "idx_opinions_uuid" ON "opinions" ("uuid");

CREATE TABLE "organisations" (
    "id" serial NOT NULL,
    "name" varchar(255) DEFAULT '' NOT NULL,
    "date_created" timestamp NOT NULL,
    "date_modified" timestamp NOT NULL,
    "description" text DEFAULT NULL,
    "type" varchar(255) DEFAULT '' NOT NULL,
    "nationality" varchar(255) DEFAULT '' NOT NULL,
    "sector" varchar(255) DEFAULT '' NOT NULL,
    "created_by" integer DEFAULT 0 NOT NULL,
    "uuid" varchar(40) DEFAULT NULL,
    "contacts" text DEFAULT NULL,
    "local" boolean DEFAULT 'FALSE' NOT NULL,
    "restricted_to_domain" text DEFAULT NULL,
    "landingpage" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_organisations_name" ON "organisations" ("name");
CREATE UNIQUE INDEX "idx_organisations_uuid" ON "organisations" ("uuid");

CREATE TABLE "org_blocklists" (
    "id" serial NOT NULL,
    "org_uuid" varchar(40) NOT NULL,
    "created" timestamp NOT NULL,
    "org_name" varchar(255) NOT NULL,
    "comment" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_org_blocklists_org_name" ON "org_blocklists" ("org_name");
CREATE UNIQUE INDEX "idx_org_blocklists_org_uuid" ON "org_blocklists" ("org_uuid");

CREATE TABLE "over_correlating_values" (
    "id" serial NOT NULL,
    "value" varchar(191) NOT NULL,
    "occurrence" integer DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_over_correlating_values_occurrence" ON "over_correlating_values" ("occurrence");
CREATE UNIQUE INDEX "idx_over_correlating_values_value" ON "over_correlating_values" ("value");

CREATE TABLE "posts" (
    "id" serial NOT NULL,
    "date_created" timestamp NOT NULL,
    "date_modified" timestamp NOT NULL,
    "user_id" integer NOT NULL,
    "contents" text NOT NULL,
    "post_id" integer DEFAULT 0 NOT NULL,
    "thread_id" integer DEFAULT 0 NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_posts_post_id" ON "posts" ("post_id");
CREATE INDEX "idx_posts_thread_id" ON "posts" ("thread_id");

CREATE TABLE "regexp" (
    "id" serial NOT NULL,
    "regexp" varchar(255) NOT NULL,
    "replacement" varchar(255) NOT NULL,
    "type" varchar(100) DEFAULT 'ALL' NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "relationships" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "object_uuid" varchar(40) NOT NULL,
    "object_type" varchar(80) NOT NULL,
    "authors" text DEFAULT NULL,
    "org_uuid" varchar(40) NOT NULL,
    "orgc_uuid" varchar(40) NOT NULL,
    "created" timestamp NOT NULL,
    "modified" timestamp NOT NULL,
    "distribution" smallint NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "locked" boolean DEFAULT 'FALSE' NOT NULL,
    "relationship_type" varchar(255) DEFAULT NULL,
    "related_object_uuid" varchar(40) NOT NULL,
    "related_object_type" varchar(80) NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_relationships_distribution" ON "relationships" ("distribution");
CREATE INDEX "idx_relationships_object_type" ON "relationships" ("object_type");
CREATE INDEX "idx_relationships_object_uuid" ON "relationships" ("object_uuid");
CREATE INDEX "idx_relationships_org_uuid" ON "relationships" ("org_uuid");
CREATE INDEX "idx_relationships_orgc_uuid" ON "relationships" ("orgc_uuid");
CREATE INDEX "idx_relationships_related_object_type" ON "relationships" ("related_object_type");
CREATE INDEX "idx_relationships_related_object_uuid" ON "relationships" ("related_object_uuid");
CREATE INDEX "idx_relationships_relationship_type" ON "relationships" ("relationship_type");
CREATE INDEX "idx_relationships_sharing_group_id" ON "relationships" ("sharing_group_id");
CREATE UNIQUE INDEX "idx_relationships_uuid" ON "relationships" ("uuid");

CREATE TABLE "rest_client_histories" (
    "id" serial NOT NULL,
    "org_id" integer NOT NULL,
    "user_id" integer NOT NULL,
    "headers" text DEFAULT NULL,
    "body" text DEFAULT NULL,
    "url" text DEFAULT NULL,
    "http_method" varchar(255) DEFAULT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "use_full_path" boolean DEFAULT 'FALSE',
    "show_result" boolean DEFAULT 'FALSE',
    "skip_ssl" boolean DEFAULT 'FALSE',
    "outcome" integer NOT NULL,
    "bookmark" boolean DEFAULT 'FALSE' NOT NULL,
    "bookmark_name" varchar(255) DEFAULT '',
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_rest_client_histories_org_id" ON "rest_client_histories" ("org_id");
CREATE INDEX "idx_rest_client_histories_timestamp" ON "rest_client_histories" ("timestamp");
CREATE INDEX "idx_rest_client_histories_user_id" ON "rest_client_histories" ("user_id");

CREATE TABLE "roles" (
    "id" serial NOT NULL,
    "name" varchar(100) NOT NULL,
    "created" timestamp ,
    "modified" timestamp ,
    "perm_add" boolean DEFAULT NULL,
    "perm_modify" boolean DEFAULT NULL,
    "perm_modify_org" boolean DEFAULT NULL,
    "perm_publish" boolean DEFAULT NULL,
    "perm_delegate" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_sync" boolean DEFAULT NULL,
    "perm_admin" boolean DEFAULT NULL,
    "perm_audit" boolean DEFAULT NULL,
    "perm_full" boolean DEFAULT NULL,
    "perm_auth" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_site_admin" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_regexp_access" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_tagger" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_template" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_sharing_group" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_tag_editor" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_sighting" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_object_template" boolean DEFAULT 'FALSE' NOT NULL,
    "default_role" boolean DEFAULT 'FALSE' NOT NULL,
    "memory_limit" varchar(255) DEFAULT '',
    "max_execution_time" varchar(255) DEFAULT '',
    "restricted_to_site_admin" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_publish_zmq" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_publish_kafka" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_decaying" boolean DEFAULT 'FALSE' NOT NULL,
    "enforce_rate_limit" boolean DEFAULT 'FALSE' NOT NULL,
    "rate_limit_count" integer DEFAULT 0 NOT NULL,
    "perm_galaxy_editor" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_warninglist" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_view_feed_correlations" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_analyst_data" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_skip_otp" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_server_sign" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_sync_internal" boolean DEFAULT 'FALSE' NOT NULL,
    "perm_sync_authoritative" boolean DEFAULT 'FALSE' NOT NULL,
    "restsearch_limit_result" integer DEFAULT 0,
    "perm_ai_tools" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "scheduled_tasks" (
    "id" serial NOT NULL,
    "type" varchar(100) NOT NULL,
    "timer" integer NOT NULL,
    "last_job_id" integer DEFAULT NULL,
    "description" varchar(255) NOT NULL,
    "next_execution_time" integer NOT NULL,
    "message" varchar(255) NOT NULL,
    "user_id" integer NOT NULL,
    "action" varchar(40) NOT NULL,
    "params" varchar(255) DEFAULT NULL,
    "enabled" boolean DEFAULT 'FALSE',
    "last_run_at" integer DEFAULT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "schema_migrations" (
    "id" serial NOT NULL,
    "migration_id" varchar(191) NOT NULL,
    "applied_at" timestamp NOT NULL,
    "duration_ms" integer DEFAULT 0 NOT NULL,
    "status" varchar(16) DEFAULT 'applied' NOT NULL,
    "error" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_schema_migrations_migration_id" ON "schema_migrations" ("migration_id");

CREATE TABLE "servers" (
    "id" serial NOT NULL,
    "name" varchar(255) NOT NULL,
    "url" varchar(255) NOT NULL,
    "authkey" bytea NOT NULL,
    "org_id" integer NOT NULL,
    "push" boolean NOT NULL,
    "pull" boolean NOT NULL,
    "push_sightings" boolean DEFAULT 'FALSE' NOT NULL,
    "push_galaxy_clusters" boolean DEFAULT 'FALSE' NOT NULL,
    "push_analyst_data" boolean DEFAULT 'FALSE' NOT NULL,
    "pull_analyst_data" boolean DEFAULT 'FALSE' NOT NULL,
    "pull_galaxy_clusters" boolean DEFAULT 'FALSE' NOT NULL,
    "push_collections" boolean DEFAULT 'FALSE' NOT NULL,
    "pull_collections" boolean DEFAULT 'FALSE' NOT NULL,
    "lastpulledid" integer DEFAULT NULL,
    "lastpushedid" integer DEFAULT NULL,
    "organization" varchar(10) DEFAULT NULL,
    "remote_org_id" integer NOT NULL,
    "publish_without_email" boolean DEFAULT 'FALSE' NOT NULL,
    "unpublish_event" boolean DEFAULT 'FALSE' NOT NULL,
    "self_signed" boolean NOT NULL,
    "pull_rules" text NOT NULL,
    "push_rules" text NOT NULL,
    "cert_file" varchar(255) DEFAULT NULL,
    "client_cert_file" varchar(255) DEFAULT NULL,
    "internal" boolean DEFAULT 'FALSE' NOT NULL,
    "skip_proxy" boolean DEFAULT 'FALSE' NOT NULL,
    "remove_missing_tags" boolean DEFAULT 'FALSE' NOT NULL,
    "caching_enabled" boolean DEFAULT 'FALSE' NOT NULL,
    "priority" integer DEFAULT 0 NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_servers_org_id" ON "servers" ("org_id");
CREATE INDEX "idx_servers_priority" ON "servers" ("priority");
CREATE INDEX "idx_servers_remote_org_id" ON "servers" ("remote_org_id");

CREATE TABLE "shadow_attributes" (
    "id" serial NOT NULL,
    "old_id" integer DEFAULT 0,
    "event_id" integer NOT NULL,
    "type" varchar(100) NOT NULL,
    "category" varchar(255) NOT NULL,
    "value1" text DEFAULT NULL,
    "to_ids" boolean DEFAULT 'TRUE' NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "value2" text DEFAULT NULL,
    "org_id" integer NOT NULL,
    "email" varchar(255) DEFAULT NULL,
    "event_org_id" integer NOT NULL,
    "comment" text NOT NULL,
    "event_uuid" varchar(40) NOT NULL,
    "deleted" boolean DEFAULT 'FALSE' NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "proposal_to_delete" boolean DEFAULT 'FALSE' NOT NULL,
    "disable_correlation" boolean DEFAULT 'FALSE' NOT NULL,
    "first_seen" bigint DEFAULT NULL,
    "last_seen" bigint DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_shadow_attributes_category" ON "shadow_attributes" ("category");
CREATE INDEX "idx_shadow_attributes_event_id" ON "shadow_attributes" ("event_id");
CREATE INDEX "idx_shadow_attributes_event_org_id" ON "shadow_attributes" ("event_org_id");
CREATE INDEX "idx_shadow_attributes_event_uuid" ON "shadow_attributes" ("event_uuid");
CREATE INDEX "idx_shadow_attributes_first_seen" ON "shadow_attributes" ("first_seen");
CREATE INDEX "idx_shadow_attributes_last_seen" ON "shadow_attributes" ("last_seen");
CREATE INDEX "idx_shadow_attributes_old_id" ON "shadow_attributes" ("old_id");
CREATE INDEX "idx_shadow_attributes_type" ON "shadow_attributes" ("type");
CREATE INDEX "idx_shadow_attributes_uuid" ON "shadow_attributes" ("uuid");
CREATE INDEX "idx_shadow_attributes_value1" ON "shadow_attributes" USING hash ("value1");
CREATE INDEX "idx_shadow_attributes_value2" ON "shadow_attributes" USING hash ("value2");

CREATE TABLE "shadow_attribute_correlations" (
    "id" serial NOT NULL,
    "org_id" integer NOT NULL,
    "value" text NOT NULL,
    "distribution" smallint NOT NULL,
    "a_distribution" smallint NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "a_sharing_group_id" integer DEFAULT NULL,
    "attribute_id" integer NOT NULL,
    "1_shadow_attribute_id" integer NOT NULL,
    "event_id" integer NOT NULL,
    "1_event_id" integer NOT NULL,
    "info" text NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_shadow_attribute_correlations_1_event_id" ON "shadow_attribute_correlations" ("1_event_id");
CREATE INDEX "idx_shadow_attribute_correlations_1_shadow_attribute_id" ON "shadow_attribute_correlations" ("1_shadow_attribute_id");
CREATE INDEX "idx_shadow_attribute_correlations_a_sharing_group_id" ON "shadow_attribute_correlations" ("a_sharing_group_id");
CREATE INDEX "idx_shadow_attribute_correlations_attribute_id" ON "shadow_attribute_correlations" ("attribute_id");
CREATE INDEX "idx_shadow_attribute_correlations_event_id" ON "shadow_attribute_correlations" ("event_id");
CREATE INDEX "idx_shadow_attribute_correlations_org_id" ON "shadow_attribute_correlations" ("org_id");
CREATE INDEX "idx_shadow_attribute_correlations_sharing_group_id" ON "shadow_attribute_correlations" ("sharing_group_id");

CREATE TABLE "sharing_groups" (
    "id" serial NOT NULL,
    "name" varchar(255) NOT NULL,
    "releasability" text NOT NULL,
    "description" text NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "organisation_uuid" varchar(40) NOT NULL,
    "org_id" integer NOT NULL,
    "sync_user_id" integer DEFAULT 0 NOT NULL,
    "active" boolean NOT NULL,
    "created" timestamp NOT NULL,
    "modified" timestamp NOT NULL,
    "local" boolean NOT NULL,
    "roaming" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_sharing_groups_name" ON "sharing_groups" ("name");
CREATE INDEX "idx_sharing_groups_org_id" ON "sharing_groups" ("org_id");
CREATE INDEX "idx_sharing_groups_organisation_uuid" ON "sharing_groups" ("organisation_uuid");
CREATE INDEX "idx_sharing_groups_sync_user_id" ON "sharing_groups" ("sync_user_id");
CREATE UNIQUE INDEX "idx_sharing_groups_uuid" ON "sharing_groups" ("uuid");

CREATE TABLE "sharing_group_blueprints" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "name" varchar(191) NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "user_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "sharing_group_id" integer DEFAULT NULL,
    "rules" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_sharing_group_blueprints_name" ON "sharing_group_blueprints" ("name");
CREATE INDEX "idx_sharing_group_blueprints_org_id" ON "sharing_group_blueprints" ("org_id");
CREATE INDEX "idx_sharing_group_blueprints_sharing_group_id" ON "sharing_group_blueprints" ("sharing_group_id");
CREATE INDEX "idx_sharing_group_blueprints_uuid" ON "sharing_group_blueprints" ("uuid");

CREATE TABLE "sharing_group_orgs" (
    "id" serial NOT NULL,
    "sharing_group_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "extend" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_sharing_group_orgs_org_id" ON "sharing_group_orgs" ("org_id");
CREATE INDEX "idx_sharing_group_orgs_sharing_group_id" ON "sharing_group_orgs" ("sharing_group_id");

CREATE TABLE "sharing_group_servers" (
    "id" serial NOT NULL,
    "sharing_group_id" integer NOT NULL,
    "server_id" integer NOT NULL,
    "all_orgs" boolean NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_sharing_group_servers_server_id" ON "sharing_group_servers" ("server_id");
CREATE INDEX "idx_sharing_group_servers_sharing_group_id" ON "sharing_group_servers" ("sharing_group_id");

CREATE TABLE "sightingdbs" (
    "id" serial NOT NULL,
    "name" varchar(255) NOT NULL,
    "description" text DEFAULT NULL,
    "owner" varchar(255) DEFAULT '',
    "host" varchar(255) DEFAULT 'http://localhost',
    "port" integer DEFAULT 9999,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "enabled" boolean DEFAULT 'FALSE' NOT NULL,
    "skip_proxy" boolean DEFAULT 'FALSE' NOT NULL,
    "ssl_skip_verification" boolean DEFAULT 'FALSE' NOT NULL,
    "namespace" varchar(255) DEFAULT '',
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_sightingdbs_host" ON "sightingdbs" ("host");
CREATE INDEX "idx_sightingdbs_name" ON "sightingdbs" ("name");
CREATE INDEX "idx_sightingdbs_owner" ON "sightingdbs" ("owner");
CREATE INDEX "idx_sightingdbs_port" ON "sightingdbs" ("port");

CREATE TABLE "sightingdb_orgs" (
    "id" serial NOT NULL,
    "sightingdb_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_sightingdb_orgs_org_id" ON "sightingdb_orgs" ("org_id");
CREATE INDEX "idx_sightingdb_orgs_sightingdb_id" ON "sightingdb_orgs" ("sightingdb_id");

CREATE TABLE "sightings" (
    "id" serial NOT NULL,
    "attribute_id" integer NOT NULL,
    "event_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "date_sighting" bigint NOT NULL,
    "uuid" varchar(255) DEFAULT '',
    "source" varchar(255) DEFAULT '',
    "type" integer DEFAULT 0,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_sightings_attribute_id" ON "sightings" ("attribute_id");
CREATE INDEX "idx_sightings_event_id" ON "sightings" ("event_id");
CREATE INDEX "idx_sightings_org_id" ON "sightings" ("org_id");
CREATE INDEX "idx_sightings_source" ON "sightings" ("source");
CREATE INDEX "idx_sightings_type" ON "sightings" ("type");
CREATE UNIQUE INDEX "idx_sightings_uuid" ON "sightings" ("uuid");

CREATE TABLE "sighting_blocklists" (
    "id" serial NOT NULL,
    "org_uuid" varchar(40) NOT NULL,
    "created" timestamp NOT NULL,
    "org_name" varchar(255) NOT NULL,
    "comment" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_sighting_blocklists_org_name" ON "sighting_blocklists" ("org_name");
CREATE INDEX "idx_sighting_blocklists_org_uuid" ON "sighting_blocklists" ("org_uuid");

CREATE TABLE "system_settings" (
    "id" serial NOT NULL,
    "setting" varchar(255) NOT NULL,
    "value" bytea NOT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_system_settings_setting" ON "system_settings" ("setting");

CREATE TABLE "tags" (
    "id" serial NOT NULL,
    "name" varchar(255) NOT NULL,
    "colour" varchar(7) NOT NULL,
    "exportable" boolean NOT NULL,
    "org_id" integer DEFAULT 0 NOT NULL,
    "user_id" integer DEFAULT 0 NOT NULL,
    "hide_tag" boolean DEFAULT 'FALSE' NOT NULL,
    "numerical_value" integer DEFAULT NULL,
    "is_galaxy" boolean DEFAULT 'FALSE' NOT NULL,
    "is_custom_galaxy" boolean DEFAULT 'FALSE' NOT NULL,
    "local_only" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_tags_name" ON "tags" ("name");
CREATE INDEX "idx_tags_numerical_value" ON "tags" ("numerical_value");
CREATE INDEX "idx_tags_org_id" ON "tags" ("org_id");
CREATE INDEX "idx_tags_user_id" ON "tags" ("user_id");
CREATE UNIQUE INDEX "idx_tags_name_lower" ON "tags" (lower("name"));

CREATE TABLE "tag_collections" (
    "id" serial NOT NULL,
    "uuid" varchar(40) DEFAULT NULL,
    "user_id" integer NOT NULL,
    "org_id" integer NOT NULL,
    "name" varchar(255) NOT NULL,
    "description" text NOT NULL,
    "all_orgs" boolean DEFAULT 'FALSE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_tag_collections_org_id" ON "tag_collections" ("org_id");
CREATE INDEX "idx_tag_collections_user_id" ON "tag_collections" ("user_id");
CREATE UNIQUE INDEX "idx_tag_collections_uuid" ON "tag_collections" ("uuid");

CREATE TABLE "tag_collection_tags" (
    "id" serial NOT NULL,
    "tag_collection_id" integer NOT NULL,
    "tag_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_tag_collection_tags_tag_collection_id" ON "tag_collection_tags" ("tag_collection_id");
CREATE INDEX "idx_tag_collection_tags_tag_id" ON "tag_collection_tags" ("tag_id");

CREATE TABLE "tasks" (
    "id" serial NOT NULL,
    "type" varchar(100) NOT NULL,
    "timer" integer NOT NULL,
    "scheduled_time" varchar(8) DEFAULT '6:00' NOT NULL,
    "process_id" varchar(32) DEFAULT NULL,
    "description" varchar(255) NOT NULL,
    "next_execution_time" integer NOT NULL,
    "message" varchar(255) NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "taxii_servers" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "name" varchar(191) NOT NULL,
    "owner" varchar(191) NOT NULL,
    "discovery_url" varchar(512) DEFAULT NULL,
    "api_root" varchar(1024) DEFAULT NULL,
    "description" text DEFAULT NULL,
    "filters" text DEFAULT NULL,
    "api_key" text NOT NULL,
    "auth_type" varchar(191) DEFAULT 'basic',
    "collection" varchar(40) DEFAULT NULL,
    "skip_proxy" boolean DEFAULT 'FALSE' NOT NULL,
    "enabled" boolean DEFAULT 'TRUE' NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_taxii_servers_baseurl" ON "taxii_servers" ("discovery_url");
CREATE INDEX "idx_taxii_servers_name" ON "taxii_servers" ("name");
CREATE INDEX "idx_taxii_servers_uuid" ON "taxii_servers" ("uuid");

CREATE TABLE "taxonomies" (
    "id" serial NOT NULL,
    "namespace" varchar(255) NOT NULL,
    "description" text NOT NULL,
    "version" integer NOT NULL,
    "enabled" boolean DEFAULT 'FALSE' NOT NULL,
    "exclusive" boolean DEFAULT 'FALSE',
    "required" boolean DEFAULT 'FALSE' NOT NULL,
    "highlighted" boolean DEFAULT 'FALSE',
    PRIMARY KEY ("id")
);

CREATE TABLE "taxonomy_entries" (
    "id" serial NOT NULL,
    "taxonomy_predicate_id" integer NOT NULL,
    "value" text NOT NULL,
    "expanded" text DEFAULT NULL,
    "colour" varchar(7) DEFAULT NULL,
    "description" text DEFAULT NULL,
    "numerical_value" integer DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_taxonomy_entries_numerical_value" ON "taxonomy_entries" ("numerical_value");
CREATE INDEX "idx_taxonomy_entries_taxonomy_predicate_id" ON "taxonomy_entries" ("taxonomy_predicate_id");

CREATE TABLE "taxonomy_predicates" (
    "id" serial NOT NULL,
    "taxonomy_id" integer NOT NULL,
    "value" text NOT NULL,
    "expanded" text DEFAULT NULL,
    "colour" varchar(7) DEFAULT NULL,
    "description" text DEFAULT NULL,
    "exclusive" boolean DEFAULT 'FALSE',
    "numerical_value" integer DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_taxonomy_predicates_numerical_value" ON "taxonomy_predicates" ("numerical_value");
CREATE INDEX "idx_taxonomy_predicates_taxonomy_id" ON "taxonomy_predicates" ("taxonomy_id");

CREATE TABLE "templates" (
    "id" serial NOT NULL,
    "name" varchar(255) NOT NULL,
    "description" varchar(255) NOT NULL,
    "org" varchar(255) NOT NULL,
    "share" boolean NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "template_elements" (
    "id" serial NOT NULL,
    "template_id" integer NOT NULL,
    "position" integer NOT NULL,
    "element_definition" varchar(255) NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "template_element_attributes" (
    "id" serial NOT NULL,
    "template_element_id" integer NOT NULL,
    "name" varchar(255) NOT NULL,
    "description" text NOT NULL,
    "to_ids" boolean DEFAULT 'TRUE' NOT NULL,
    "category" varchar(255) NOT NULL,
    "complex" boolean NOT NULL,
    "type" varchar(255) NOT NULL,
    "mandatory" boolean NOT NULL,
    "batch" boolean NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "template_element_files" (
    "id" serial NOT NULL,
    "template_element_id" integer NOT NULL,
    "name" varchar(255) NOT NULL,
    "description" text NOT NULL,
    "category" varchar(255) NOT NULL,
    "malware" boolean NOT NULL,
    "mandatory" boolean NOT NULL,
    "batch" boolean NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "template_element_texts" (
    "id" serial NOT NULL,
    "name" varchar(255) NOT NULL,
    "template_element_id" integer NOT NULL,
    "text" text NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "template_tags" (
    "id" serial NOT NULL,
    "template_id" integer NOT NULL,
    "tag_id" integer NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "threads" (
    "id" serial NOT NULL,
    "date_created" timestamp NOT NULL,
    "date_modified" timestamp NOT NULL,
    "distribution" smallint NOT NULL,
    "user_id" integer NOT NULL,
    "post_count" integer NOT NULL,
    "event_id" integer NOT NULL,
    "title" varchar(255) NOT NULL,
    "org_id" integer NOT NULL,
    "sharing_group_id" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_threads_event_id" ON "threads" ("event_id");
CREATE INDEX "idx_threads_org_id" ON "threads" ("org_id");
CREATE INDEX "idx_threads_sharing_group_id" ON "threads" ("sharing_group_id");
CREATE INDEX "idx_threads_user_id" ON "threads" ("user_id");

CREATE TABLE "threat_levels" (
    "id" serial NOT NULL,
    "name" varchar(50) NOT NULL,
    "description" varchar(255) DEFAULT NULL,
    "form_description" varchar(255) NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "users" (
    "id" serial NOT NULL,
    "password" varchar(255) NOT NULL,
    "org_id" integer NOT NULL,
    "server_id" integer DEFAULT 0 NOT NULL,
    "email" varchar(255) NOT NULL,
    "autoalert" boolean DEFAULT 'FALSE' NOT NULL,
    "authkey" varchar(40) DEFAULT NULL,
    "invited_by" integer DEFAULT 0 NOT NULL,
    "gpgkey" text DEFAULT NULL,
    "certif_public" text DEFAULT NULL,
    "nids_sid" integer DEFAULT 0 NOT NULL,
    "termsaccepted" boolean DEFAULT 'FALSE' NOT NULL,
    "newsread" integer DEFAULT 0,
    "role_id" integer DEFAULT 0 NOT NULL,
    "change_pw" boolean DEFAULT 'FALSE' NOT NULL,
    "contactalert" boolean DEFAULT 'FALSE' NOT NULL,
    "disabled" boolean DEFAULT 'FALSE' NOT NULL,
    "expiration" timestamp ,
    "current_login" integer DEFAULT 0,
    "last_login" integer DEFAULT 0,
    "force_logout" boolean DEFAULT 'FALSE' NOT NULL,
    "date_created" bigint DEFAULT NULL,
    "date_modified" bigint DEFAULT NULL,
    "sub" varchar(255) DEFAULT NULL,
    "external_auth_required" boolean DEFAULT 'FALSE' NOT NULL,
    "external_auth_key" text DEFAULT NULL,
    "last_api_access" integer DEFAULT 0,
    "notification_daily" boolean DEFAULT 'FALSE' NOT NULL,
    "notification_weekly" boolean DEFAULT 'FALSE' NOT NULL,
    "notification_monthly" boolean DEFAULT 'FALSE' NOT NULL,
    "totp" varchar(255) DEFAULT NULL,
    "hotp_counter" integer DEFAULT NULL,
    "last_pw_change" bigint DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "idx_users_email" ON "users" ("email");
CREATE INDEX "idx_users_org_id" ON "users" ("org_id");
CREATE INDEX "idx_users_server_id" ON "users" ("server_id");
CREATE UNIQUE INDEX "idx_users_sub" ON "users" ("sub");

CREATE TABLE "user_login_profiles" (
    "id" serial NOT NULL,
    "created_at" timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "user_id" integer NOT NULL,
    "status" varchar(191) DEFAULT NULL,
    "ip" varchar(191) DEFAULT NULL,
    "user_agent" varchar(191) DEFAULT NULL,
    "accept_lang" varchar(191) DEFAULT NULL,
    "geoip" varchar(191) DEFAULT NULL,
    "ua_platform" varchar(191) DEFAULT NULL,
    "ua_browser" varchar(191) DEFAULT NULL,
    "ua_pattern" varchar(191) DEFAULT NULL,
    "hash" varchar(32) NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_user_login_profiles_geoip" ON "user_login_profiles" ("geoip");
CREATE UNIQUE INDEX "idx_user_login_profiles_hash" ON "user_login_profiles" ("hash");
CREATE INDEX "idx_user_login_profiles_ip" ON "user_login_profiles" ("ip");
CREATE INDEX "idx_user_login_profiles_status" ON "user_login_profiles" ("status");
CREATE INDEX "idx_user_login_profiles_user_id" ON "user_login_profiles" ("user_id");

CREATE TABLE "user_settings" (
    "id" serial NOT NULL,
    "setting" varchar(255) NOT NULL,
    "value" text NOT NULL,
    "user_id" integer NOT NULL,
    "timestamp" integer NOT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_user_settings_setting" ON "user_settings" ("setting");
CREATE UNIQUE INDEX "idx_user_settings_unique_setting" ON "user_settings" ("user_id", "setting");
CREATE INDEX "idx_user_settings_user_id" ON "user_settings" ("user_id");

CREATE TABLE "warninglists" (
    "id" serial NOT NULL,
    "name" varchar(255) NOT NULL,
    "type" varchar(255) DEFAULT 'string' NOT NULL,
    "description" text NOT NULL,
    "version" integer DEFAULT 1 NOT NULL,
    "enabled" boolean DEFAULT 'FALSE' NOT NULL,
    "default" boolean DEFAULT 'TRUE' NOT NULL,
    "category" varchar(20) DEFAULT 'false_positive' NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "warninglist_entries" (
    "id" serial NOT NULL,
    "value" text NOT NULL,
    "warninglist_id" integer NOT NULL,
    "comment" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_warninglist_entries_warninglist_id" ON "warninglist_entries" ("warninglist_id");

CREATE TABLE "warninglist_types" (
    "id" serial NOT NULL,
    "type" varchar(255) NOT NULL,
    "warninglist_id" integer NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "workflows" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "name" varchar(191) NOT NULL,
    "description" varchar(191) NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "enabled" boolean DEFAULT 'FALSE' NOT NULL,
    "counter" integer DEFAULT 0 NOT NULL,
    "trigger_id" varchar(191) NOT NULL,
    "debug_enabled" boolean DEFAULT 'FALSE' NOT NULL,
    "data" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_workflows_name" ON "workflows" ("name");
CREATE INDEX "idx_workflows_timestamp" ON "workflows" ("timestamp");
CREATE INDEX "idx_workflows_trigger_id" ON "workflows" ("trigger_id");
CREATE INDEX "idx_workflows_uuid" ON "workflows" ("uuid");

CREATE TABLE "workflow_blueprints" (
    "id" serial NOT NULL,
    "uuid" varchar(40) NOT NULL,
    "name" varchar(191) NOT NULL,
    "description" varchar(191) NOT NULL,
    "timestamp" integer DEFAULT 0 NOT NULL,
    "default" boolean DEFAULT 'FALSE' NOT NULL,
    "data" text DEFAULT NULL,
    PRIMARY KEY ("id")
);
CREATE INDEX "idx_workflow_blueprints_name" ON "workflow_blueprints" ("name");
CREATE INDEX "idx_workflow_blueprints_timestamp" ON "workflow_blueprints" ("timestamp");
CREATE INDEX "idx_workflow_blueprints_uuid" ON "workflow_blueprints" ("uuid");

-- --------------------------------------------------------

--
-- Default values for initial installation
--

INSERT INTO "admin_settings" ("id", "setting", "value") VALUES (1, 'db_version', '159') ON CONFLICT DO NOTHING;
INSERT INTO "admin_settings" ("id", "setting", "value") VALUES (8, 'fix_login', FLOOR(EXTRACT(EPOCH FROM NOW()))::bigint::text) ON CONFLICT DO NOTHING;
INSERT INTO "admin_settings" ("id", "setting", "value") VALUES (9, 'default_role', '3') ON CONFLICT DO NOTHING;

INSERT INTO "feeds" ("id", "name", "provider", "url", "rules", "enabled", "distribution", "sharing_group_id", "tag_id", "default", "source_format", "fixed_event", "delta_merge", "event_id", "publish", "override_ids", "settings", "input_source", "delete_local_file", "lookup_visible", "headers", "caching_enabled", "force_to_ids", "orgc_id", "tag_collection_id", "lock_events") VALUES
(1, 'CIRCL OSINT Feed', 'CIRCL', 'https://www.circl.lu/doc/misp/feed-osint', NULL, 'FALSE', 3, 0, 0, 'TRUE', 'misp', 'FALSE', 'FALSE', 0, 'FALSE', 'FALSE', NULL, 'network', 'FALSE', 'FALSE', NULL, 'FALSE', 'FALSE', 0, 0, 'FALSE'),
(2, 'The Botvrij.eu Data', 'Botvrij.eu', 'https://www.botvrij.eu/data/feed-osint', NULL, 'FALSE', 3, 0, 0, 'TRUE', 'misp', 'FALSE', 'FALSE', 0, 'FALSE', 'FALSE', NULL, 'network', 'FALSE', 'FALSE', NULL, 'FALSE', 'FALSE', 0, 0, 'FALSE')
ON CONFLICT DO NOTHING;

INSERT INTO "regexp" ("id", "regexp", "replacement", "type") VALUES
(1, '/.:.ProgramData./i', '%ALLUSERSPROFILE%\\', 'ALL'),
(2, '/.:.Documents and Settings.All Users./i', '%ALLUSERSPROFILE%\\', 'ALL'),
(3, '/.:.Program Files.Common Files./i', '%COMMONPROGRAMFILES%\\', 'ALL'),
(4, '/.:.Program Files (x86).Common Files./i', '%COMMONPROGRAMFILES(x86)%\\', 'ALL'),
(5, '/.:.Users\\(.*?)\\AppData.Local.Temp./i', '%TEMP%\\', 'ALL'),
(6, '/.:.ProgramData./i', '%PROGRAMDATA%\\', 'ALL'),
(7, '/.:.Program Files./i', '%PROGRAMFILES%\\', 'ALL'),
(8, '/.:.Program Files (x86)./i', '%PROGRAMFILES(X86)%\\', 'ALL'),
(9, '/.:.Users.Public./i', '%PUBLIC%\\', 'ALL'),
(10, '/.:.Documents and Settings\\(.*?)\\Local Settings.Temp./i', '%TEMP%\\', 'ALL'),
(11, '/.:.Users\\(.*?)\\AppData.Local.Temp./i', '%TEMP%\\', 'ALL'),
(12, '/.:.Users\\(.*?)\\AppData.Local./i', '%LOCALAPPDATA%\\', 'ALL'),
(13, '/.:.Users\\(.*?)\\AppData.Roaming./i', '%APPDATA%\\', 'ALL'),
(14, '/.:.Users\\(.*?)\\Application Data./i', '%APPDATA%\\', 'ALL'),
(15, '/.:.Windows\\(.*?)\\Application Data./i', '%APPDATA%\\', 'ALL'),
(16, '/.:.Users\\(.*?)\\/i', '%USERPROFILE%\\', 'ALL'),
(17, '/.:.DOCUME~1.\\(.*?)\\/i', '%USERPROFILE%\\', 'ALL'),
(18, '/.:.Documents and Settings\\(.*?)\\/i', '%USERPROFILE%\\', 'ALL'),
(19, '/.:.Windows./i', '%WINDIR%\\', 'ALL'),
(20, '/.:.Windows./i', '%WINDIR%\\', 'ALL'),
(21, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}/i', 'HKCU', 'ALL'),
(22, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}/i', 'HKCU', 'ALL'),
(23, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}/i', 'HKCU', 'ALL'),
(24, '/.REGISTRY.MACHINE./i', 'HKLM\\', 'ALL'),
(25, '/.Registry.Machine./i', 'HKLM\\', 'ALL'),
(26, '/%USERPROFILE%.Application Data.Microsoft.UProof/i', '', 'ALL'),
(27, '/%USERPROFILE%.Local Settings.History/i', '', 'ALL'),
(28, '/%APPDATA%.Microsoft.UProof/i ', '', 'ALL'),
(29, '/%LOCALAPPDATA%.Microsoft.Windows.Temporary Internet Files/i', '', 'ALL')
ON CONFLICT DO NOTHING;

INSERT INTO "roles" ("id", "name", "created", "modified", "perm_add", "perm_modify", "perm_modify_org", "perm_publish", "perm_delegate", "perm_sync", "perm_admin", "perm_audit", "perm_full", "perm_auth", "perm_site_admin", "perm_regexp_access", "perm_tagger", "perm_template", "perm_sharing_group", "perm_tag_editor", "perm_sighting", "perm_object_template", "default_role", "memory_limit", "max_execution_time", "restricted_to_site_admin", "perm_publish_zmq", "perm_publish_kafka", "perm_decaying", "enforce_rate_limit", "rate_limit_count", "perm_galaxy_editor", "perm_warninglist", "perm_view_feed_correlations", "perm_analyst_data", "perm_skip_otp", "perm_server_sign", "perm_sync_internal", "perm_sync_authoritative", "restsearch_limit_result", "perm_ai_tools") VALUES
(1, 'admin', NOW(), NOW(), 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', NULL, NULL, 'FALSE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 0, 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 0, 'TRUE'),
(2, 'Org Admin', NOW(), NOW(), 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 'TRUE', 'TRUE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 'FALSE', NULL, NULL, 'FALSE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 0, 'TRUE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 0, 'FALSE'),
(3, 'User', NOW(), NOW(), 'TRUE', 'TRUE', 'TRUE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'TRUE', NULL, NULL, 'FALSE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 0, 'TRUE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 0, 'FALSE'),
(4, 'Publisher', NOW(), NOW(), 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', NULL, NULL, 'FALSE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 0, 'TRUE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 0, 'FALSE'),
(5, 'Sync user', NOW(), NOW(), 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 'TRUE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 'FALSE', NULL, NULL, 'FALSE', 'TRUE', 'TRUE', 'TRUE', 'FALSE', 0, 'TRUE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 0, 'FALSE'),
(6, 'Read Only', NOW(), NOW(), 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'TRUE', 'FALSE', 'TRUE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', NULL, NULL, 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 0, 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 'FALSE', 0, 'FALSE')
ON CONFLICT DO NOTHING;

INSERT INTO "threat_levels" ("id", "name", "description", "form_description") VALUES
(1, 'High', '*high* means sophisticated APT malware or 0-day attack', 'Sophisticated APT malware or 0-day attack'),
(2, 'Medium', '*medium* means APT malware', 'APT malware'),
(3, 'Low', '*low* means mass-malware', 'Mass-malware'),
(4, 'Undefined', '*undefined* no risk', 'No risk')
ON CONFLICT DO NOTHING;

INSERT INTO "templates" ("id", "name", "description", "org", "share") VALUES
(1, 'Phishing E-mail', 'Create a MISP event about a Phishing E-mail.', 'MISP', 'TRUE'),
(2, 'Phishing E-mail with malicious attachment', 'A MISP event based on Spear-phishing containing a malicious attachment. This event can include anything from the description of the e-mail itself, the malicious attachment and its description as well as the results of the analysis done on the malicious f', 'MISP', 'TRUE'),
(3, 'Malware Report', 'This is a template for a generic malware report. ', 'MISP', 'TRUE'),
(4, 'Indicator List', 'A simple template for indicator lists.', 'MISP', 'TRUE')
ON CONFLICT DO NOTHING;

INSERT INTO "template_elements" ("id", "template_id", "position", "element_definition") VALUES
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
(47, 4, 3, 'attribute')
ON CONFLICT DO NOTHING;

INSERT INTO "template_element_attributes" ("id", "template_element_id", "name", "description", "to_ids", "category", "complex", "type", "mandatory", "batch") VALUES
(1, 1, 'From address', 'The source address from which the e-mail was sent.', 'TRUE', 'Payload delivery', 'FALSE', 'email-src', 'TRUE', 'TRUE'),
(2, 2, 'Malicious url', 'The malicious url in the e-mail body.', 'TRUE', 'Payload delivery', 'FALSE', 'url', 'TRUE', 'TRUE'),
(3, 4, 'E-mail subject', 'The subject line of the e-mail.', 'FALSE', 'Payload delivery', 'FALSE', 'email-subject', 'TRUE', 'FALSE'),
(4, 6, 'Spoofed source address', 'If an e-mail address was spoofed, specify which.', 'TRUE', 'Payload delivery', 'FALSE', 'email-src', 'FALSE', 'FALSE'),
(5, 7, 'Source IP', 'The source IP from which the e-mail was sent', 'TRUE', 'Payload delivery', 'FALSE', 'ip-src', 'FALSE', 'TRUE'),
(6, 8, 'X-mailer header', 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 'TRUE', 'Payload delivery', 'FALSE', 'text', 'FALSE', 'TRUE'),
(7, 12, 'From address', 'The source address from which the e-mail was sent', 'TRUE', 'Payload delivery', 'FALSE', 'email-src', 'TRUE', 'TRUE'),
(8, 15, 'Spoofed From Address', 'The spoofed source address from which the e-mail appears to be sent.', 'TRUE', 'Payload delivery', 'FALSE', 'email-src', 'FALSE', 'TRUE'),
(9, 17, 'E-mail Source IP', 'The IP address from which the e-mail was sent.', 'TRUE', 'Payload delivery', 'FALSE', 'ip-src', 'FALSE', 'TRUE'),
(10, 18, 'X-mailer header', 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 'TRUE', 'Payload delivery', 'FALSE', 'text', 'FALSE', 'FALSE'),
(11, 19, 'Malicious URL in the e-mail', 'If there was a malicious URL (or several), please specify it here', 'TRUE', 'Payload delivery', 'FALSE', 'ip-dst', 'FALSE', 'TRUE'),
(12, 20, 'Exploited vulnerability', 'The vulnerabilities exploited during the payload delivery.', 'FALSE', 'Payload delivery', 'FALSE', 'vulnerability', 'FALSE', 'TRUE'),
(13, 22, 'C2 information', 'Command and Control information detected during the analysis.', 'TRUE', 'Network activity', 'TRUE', 'CnC', 'FALSE', 'TRUE'),
(14, 23, 'Artifacts dropped (File)', 'Any information about the files dropped during the analysis', 'TRUE', 'Artifacts dropped', 'TRUE', 'File', 'FALSE', 'TRUE'),
(15, 24, 'Artifacts dropped (Registry key)', 'Any registry keys touched during the analysis', 'TRUE', 'Artifacts dropped', 'FALSE', 'regkey', 'FALSE', 'TRUE'),
(16, 25, 'Artifacts dropped (Registry key + value)', 'Any registry keys created or altered together with the value.', 'TRUE', 'Artifacts dropped', 'FALSE', 'regkey|value', 'FALSE', 'TRUE'),
(17, 26, 'Persistance mechanism (filename)', 'Filenames (or filenames with filepaths) used as a persistence mechanism', 'TRUE', 'Persistence mechanism', 'FALSE', 'regkey|value', 'FALSE', 'TRUE'),
(18, 27, 'Persistence mechanism (Registry key)', 'Any registry keys touched as part of the persistence mechanism during the analysis ', 'TRUE', 'Persistence mechanism', 'FALSE', 'regkey', 'FALSE', 'TRUE'),
(19, 28, 'Persistence mechanism (Registry key + value)', 'Any registry keys created or modified together with their values used by the persistence mechanism', 'TRUE', 'Persistence mechanism', 'FALSE', 'regkey|value', 'FALSE', 'TRUE'),
(20, 34, 'C2 Information', 'You can drop any urls, domains, hostnames or IP addresses that were detected as the Command and Control during the analysis here. ', 'TRUE', 'Network activity', 'TRUE', 'CnC', 'FALSE', 'TRUE'),
(21, 35, 'Other Network Activity', 'Drop any applicable information about other network activity here. The attributes created here will NOT be marked for IDS exports.', 'FALSE', 'Network activity', 'TRUE', 'CnC', 'FALSE', 'TRUE'),
(22, 36, 'Vulnerability', 'The vulnerability or vulnerabilities that the sample exploits', 'FALSE', 'Payload delivery', 'FALSE', 'vulnerability', 'FALSE', 'TRUE'),
(23, 37, 'Artifacts Dropped (File)', 'Insert any data you have on dropped files here.', 'TRUE', 'Artifacts dropped', 'TRUE', 'File', 'FALSE', 'TRUE'),
(24, 38, 'Artifacts dropped (Registry key)', 'Any registry keys touched during the analysis', 'TRUE', 'Artifacts dropped', 'FALSE', 'regkey', 'FALSE', 'TRUE'),
(25, 39, 'Artifacts dropped (Registry key + value)', 'Any registry keys created or altered together with the value.', 'TRUE', 'Artifacts dropped', 'FALSE', 'regkey|value', 'FALSE', 'TRUE'),
(26, 42, 'Persistence mechanism (filename)', 'Insert any filenames used by the persistence mechanism.', 'TRUE', 'Persistence mechanism', 'FALSE', 'filename', 'FALSE', 'TRUE'),
(27, 43, 'Persistence Mechanism (Registry key)', 'Paste any registry keys that were created or modified as part of the persistence mechanism', 'TRUE', 'Persistence mechanism', 'FALSE', 'regkey', 'FALSE', 'TRUE'),
(28, 44, 'Persistence Mechanism (Registry key and value)', 'Paste any registry keys together with the values contained within created or modified by the persistence mechanism', 'TRUE', 'Persistence mechanism', 'FALSE', 'regkey|value', 'FALSE', 'TRUE'),
(29, 46, 'Network Indicators', 'Paste any combination of IP addresses, hostnames, domains or URL', 'TRUE', 'Network activity', 'TRUE', 'CnC', 'FALSE', 'TRUE'),
(30, 47, 'File Indicators', 'Paste any file hashes that you have (MD5, SHA1, SHA256) or filenames below. You can also add filename and hash pairs by using the following syntax for each applicable column: filename|hash ', 'TRUE', 'Payload installation', 'TRUE', 'File', 'FALSE', 'TRUE')
ON CONFLICT DO NOTHING;

INSERT INTO "template_element_files" ("id", "template_element_id", "name", "description", "category", "malware", "mandatory", "batch") VALUES
(1, 14, 'Malicious Attachment', 'The file (or files) that was (were) attached to the e-mail itself.', 'Payload delivery', 'TRUE', 'FALSE', 'TRUE'),
(2, 21, 'Payload installation', 'Payload installation detected during the analysis', 'Payload installation', 'TRUE', 'FALSE', 'TRUE'),
(3, 30, 'Malware sample', 'The sample that the report is based on', 'Payload delivery', 'TRUE', 'FALSE', 'FALSE'),
(4, 40, 'Artifacts dropped (Sample)', 'Upload any files that were dropped during the analysis.', 'Artifacts dropped', 'TRUE', 'FALSE', 'TRUE')
ON CONFLICT DO NOTHING;

INSERT INTO "template_element_texts" ("id", "name", "template_element_id", "text") VALUES
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
(12, 'Indicators', 45, 'Just paste your list of indicators based on type into the appropriate field. All of the fields are optional, so inputting a list of IP addresses into the Network indicator field for example is sufficient to complete this template.')
ON CONFLICT DO NOTHING;

INSERT INTO "org_blocklists" ("id", "org_uuid", "created", "org_name", "comment") VALUES
(3, '58d38339-7b24-4386-b4b4-4c0f950d210f', NOW(), 'Setec Astronomy', 'default example'),
(4, '58d38326-eda8-443a-9fa8-4e12950d210f', NOW(), 'Acme Finance', 'default example')
ON CONFLICT DO NOTHING;

INSERT INTO "dashboards" ("id", "uuid", "name", "description", "default", "selectable", "user_id", "restrict_to_org_id", "restrict_to_role_id", "restrict_to_permission_flag", "value", "timestamp") VALUES
(1, '5000487b-3e75-46e4-8c43-96da9dc2268b', 'Administrator', 'A comprehensive site-administrator overview: live resource monitors (CPU, memory, disk), instance usage statistics, system health rollup, sync test and cache freshness, worker queues, mail log, recent logins, API activity, and the latest users to join. Visible to site admins only.', 'FALSE', 'TRUE', 0, 0, 0, 'perm_site_admin', '[{"instance_id":"w_1","widget":"UsageDataWidget","config":{"alias":"Usage"},"position":{"x":2,"y":6,"w":4,"h":3}},{"instance_id":"w_2","widget":"NewUsersWidget","config":{"alias":"Latest users","fields":["id","date_created","Organisation.name","email"]},"position":{"x":2,"y":0,"w":4,"h":6}},{"instance_id":"w_5","widget":"LoginsWidget","config":{"alias":"Logins this month"},"position":{"x":9,"y":4,"w":3,"h":3}},{"instance_id":"w_6","widget":"APIActivityWidget","config":{"alias":"API activity","filter":[]},"position":{"x":9,"y":7,"w":3,"h":3}},{"instance_id":"w_7","widget":"BenchmarkTopListWidget","config":{"alias":"","refresh_delay":"","days":"10","field":"sql_time"},"position":{"x":0,"y":9,"w":3,"h":6}},{"instance_id":"w_8","widget":"MispAdminSyncTestWidget","config":[],"position":{"x":6,"y":7,"w":3,"h":4}},{"instance_id":"w_10","widget":"MispAdminWorkerWidget","config":{"alias":"","refresh_delay":""},"position":{"x":9,"y":10,"w":3,"h":5}},{"instance_id":"w_11","widget":"CpuLoadMonitorWidget","config":{"alias":"","window":180,"interval":3},"position":{"x":0,"y":0,"w":2,"h":3}},{"instance_id":"w_12","widget":"MemoryUsageMonitorWidget","config":{"alias":"","window":180,"interval":3},"position":{"x":0,"y":3,"w":2,"h":3}},{"instance_id":"w_13","widget":"DiskUsageMonitorWidget","config":{"path":"","threshold":85},"position":{"x":0,"y":6,"w":2,"h":3}},{"instance_id":"w_14","widget":"LoggedInUsersWidget","config":[],"position":{"x":9,"y":0,"w":3,"h":4}},{"instance_id":"w_15","widget":"MispAdminHealthWidget","config":[],"position":{"x":6,"y":0,"w":3,"h":7}},{"instance_id":"w_16","widget":"MispCacheStatusWidget","config":[],"position":{"x":6,"y":11,"w":3,"h":4}},{"instance_id":"w_17","widget":"MispMailLogWidget","config":{"log_path":"","limit":20,"lookback_bytes":65536},"position":{"x":3,"y":9,"w":3,"h":6}}]', 1789478944),
(2, '0c6b496d-b6e7-43f3-be7f-2f30215c568c', 'Analyst', 'A threat-analyst starting point: the geographic spread of recent indicators and of threat-actor origins, a live attack map, ATT&CK technique coverage, trending vulnerabilities and threat actors, new-data stats for your time window, overlap with your organisation''s data, and the latest analyst notes, opinions, and event reports.', 'TRUE', 'TRUE', 0, 0, 0, '', '[{"instance_id":"w_3","widget":"AttributeGeoMapWidget","config":{"alias":"Recent geolocated indicators by country","time_window":"7d","limit":10000,"palette":"danger","projection":"naturalEarth","sources":["ip","domain_tld","asn","country_galaxy","threat_actor"]},"position":{"x":0,"y":7,"w":3,"h":4}},{"instance_id":"w_4","widget":"ThreatActorCountryMapWidget","config":{"alias":"Threat actor origins"},"position":{"x":3,"y":7,"w":3,"h":4}},{"instance_id":"w_8","widget":"AttackWidget","config":{"alias":"","time_window":"7d","filters":{"attackGalaxy":"mitre-attack-pattern","published":[0,1]}},"position":{"x":0,"y":11,"w":12,"h":6}},{"instance_id":"w_9","widget":"TrendingWidget","config":{"alias":"Trending vulnerabilities","dimension":"vulnerability","time_window":"7d","threshold":10,"min_count":3},"position":{"x":10,"y":2,"w":2,"h":5}},{"instance_id":"w_10","widget":"NewDataStatsWidget","config":{"alias":"New data within time window","time_window":"7d","country":"","sector":""},"position":{"x":0,"y":0,"w":12,"h":2}},{"instance_id":"w_12","widget":"TrendingWidget","config":{"alias":"Trending threat actors","dimension":"threat-actor","time_window":"7d","threshold":10,"min_count":3},"position":{"x":8,"y":2,"w":2,"h":5}},{"instance_id":"w_13","widget":"PewPewMapWidget","config":{"alias":"","time_window":"7d","mode":"webgl-globe","skin":"day","max_arcs":500},"position":{"x":6,"y":7,"w":2,"h":4}},{"instance_id":"w_15","widget":"OverlapWithMyOrgWidget","config":{"alias":"Correlations to my org''s data","time_window":"7d","exclude_own_org":true},"position":{"x":8,"y":7,"w":4,"h":4}},{"instance_id":"w_19","widget":"RecentAnalystDataWidget","config":{"alias":"Notes and Opinions","time_window":"7d","limit":10},"position":{"x":0,"y":2,"w":4,"h":5}},{"instance_id":"w_20","widget":"RecentEventReportsWidget","config":{"time_window":"7d","limit":10},"position":{"x":4,"y":2,"w":4,"h":5}}]', 1789478944),
(3, '2b50c003-c475-4c9c-ac90-0a177b44e565', 'Community', 'A sharing-community overview: where the member organisations are, who contributes most (orgs and users), how the community has grown, overall usage, and the sharing relationships between organisations.', 'FALSE', 'TRUE', 0, 0, 0, '', '[{"instance_id":"w_1","widget":"OrganisationMapWidget","config":{"alias":"Organisations by country"},"position":{"x":0,"y":0,"w":8,"h":5}},{"instance_id":"w_2","widget":"UsageDataWidget","config":{"alias":"Usage"},"position":{"x":8,"y":0,"w":4,"h":5}},{"instance_id":"w_3","widget":"OrgContributionToplistWidget","config":{"alias":"Top contributing organisations"},"position":{"x":0,"y":5,"w":6,"h":4}},{"instance_id":"w_4","widget":"UserContributionToplistWidget","config":{"alias":"Top contributing users"},"position":{"x":6,"y":5,"w":6,"h":4}},{"instance_id":"w_5","widget":"OrgsEvolutionWidget","config":{"alias":"Organisation growth"},"position":{"x":0,"y":9,"w":6,"h":6}},{"instance_id":"w_6","widget":"SharingGraphWidget","config":{"alias":"Sharing relationships"},"position":{"x":6,"y":9,"w":6,"h":6}}]', 1789478944)
ON CONFLICT DO NOTHING;

INSERT INTO "schema_migrations" ("id", "migration_id", "applied_at", "duration_ms", "status", "error") VALUES
(1, '20260901_082657_taxii_servers_auth_type_width', NOW(), 161, 'applied', NULL),
(2, '20260909_175232_add_id_to_keyless_tables', NOW(), 683, 'applied', NULL),
(3, '20260915_131521_tags_name_case_insensitive', NOW(), 277, 'applied', NULL),
(4, '20260915_131522_roles_perm_ai_tools', NOW(), 129, 'applied', NULL)
ON CONFLICT DO NOTHING;

-- The rows above carry explicit ids; bring each sequence past them.
SELECT setval(pg_get_serial_sequence('admin_settings', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "admin_settings";
SELECT setval(pg_get_serial_sequence('feeds', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "feeds";
SELECT setval(pg_get_serial_sequence('regexp', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "regexp";
SELECT setval(pg_get_serial_sequence('roles', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "roles";
SELECT setval(pg_get_serial_sequence('threat_levels', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "threat_levels";
SELECT setval(pg_get_serial_sequence('templates', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "templates";
SELECT setval(pg_get_serial_sequence('template_elements', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "template_elements";
SELECT setval(pg_get_serial_sequence('template_element_attributes', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "template_element_attributes";
SELECT setval(pg_get_serial_sequence('template_element_files', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "template_element_files";
SELECT setval(pg_get_serial_sequence('template_element_texts', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "template_element_texts";
SELECT setval(pg_get_serial_sequence('org_blocklists', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "org_blocklists";
SELECT setval(pg_get_serial_sequence('dashboards', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "dashboards";
SELECT setval(pg_get_serial_sequence('schema_migrations', 'id'), COALESCE(MAX("id"), 1), MAX("id") IS NOT NULL) FROM "schema_migrations";

COMMIT;
