--
-- PostgreSQL database dump
--

-- Dumped from database version 15.2 (Debian 15.2-1.pgdg110+1)
-- Dumped by pg_dump version 15.2 (Debian 15.2-1.pgdg110+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS '';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: admin_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_settings (
    id bigint NOT NULL,
    setting character varying(255) NOT NULL,
    value text NOT NULL
);


--
-- Name: admin_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.admin_settings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: admin_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.admin_settings_id_seq OWNED BY public.admin_settings.id;


--
-- Name: allowedlist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.allowedlist (
    id bigint NOT NULL,
    name text NOT NULL
);


--
-- Name: allowedlist_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.allowedlist_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: allowedlist_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.allowedlist_id_seq OWNED BY public.allowedlist.id;


--
-- Name: attachment_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attachment_scans (
    id bigint NOT NULL,
    type character varying(40) NOT NULL,
    attribute_id bigint NOT NULL,
    infected boolean NOT NULL,
    malware_name character varying(191) DEFAULT NULL::character varying,
    "timestamp" bigint NOT NULL
);


--
-- Name: attachment_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attachment_scans_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attachment_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attachment_scans_id_seq OWNED BY public.attachment_scans.id;


--
-- Name: attribute_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attribute_tags (
    id bigint NOT NULL,
    attribute_id bigint NOT NULL,
    event_id bigint NOT NULL,
    tag_id bigint NOT NULL,
    local boolean DEFAULT false NOT NULL
);


--
-- Name: attribute_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attribute_tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attribute_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attribute_tags_id_seq OWNED BY public.attribute_tags.id;


--
-- Name: attributes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attributes (
    id bigint NOT NULL,
    event_id bigint NOT NULL,
    object_id bigint DEFAULT '0'::bigint NOT NULL,
    object_relation character varying(255) DEFAULT NULL::character varying,
    category character varying(255) NOT NULL,
    type character varying(100) NOT NULL,
    value1 text NOT NULL,
    value2 text NOT NULL,
    to_ids boolean DEFAULT true NOT NULL,
    uuid character varying(40) NOT NULL,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    distribution smallint DEFAULT '0'::smallint NOT NULL,
    sharing_group_id bigint NOT NULL,
    comment text,
    deleted boolean DEFAULT false NOT NULL,
    disable_correlation boolean DEFAULT false NOT NULL,
    first_seen bigint,
    last_seen bigint
);


--
-- Name: attributes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attributes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attributes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attributes_id_seq OWNED BY public.attributes.id;


--
-- Name: auth_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_keys (
    id bigint NOT NULL,
    uuid character varying(40) NOT NULL,
    authkey character varying(72) NOT NULL,
    authkey_start character varying(4) NOT NULL,
    authkey_end character varying(4) NOT NULL,
    created bigint NOT NULL,
    expiration bigint NOT NULL,
    user_id bigint NOT NULL,
    comment text,
    allowed_ips text,
    unique_ips text
);


--
-- Name: auth_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.auth_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: auth_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.auth_keys_id_seq OWNED BY public.auth_keys.id;


--
-- Name: bruteforces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bruteforces (
    ip character varying(255) NOT NULL,
    username character varying(255) NOT NULL,
    expire timestamp with time zone NOT NULL
);


--
-- Name: cake_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cake_sessions (
    id character varying(255) DEFAULT ''::character varying NOT NULL,
    data text NOT NULL,
    expires bigint NOT NULL
);


--
-- Name: correlations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.correlations (
    id bigint NOT NULL,
    value text NOT NULL,
    "1_event_id" bigint NOT NULL,
    "1_attribute_id" bigint NOT NULL,
    event_id bigint NOT NULL,
    attribute_id bigint NOT NULL,
    org_id bigint NOT NULL,
    distribution smallint NOT NULL,
    a_distribution smallint NOT NULL,
    sharing_group_id bigint NOT NULL,
    a_sharing_group_id bigint NOT NULL
);


--
-- Name: correlations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.correlations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: correlations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.correlations_id_seq OWNED BY public.correlations.id;


--
-- Name: dashboards; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dashboards (
    id bigint NOT NULL,
    uuid character varying(40) NOT NULL,
    name character varying(191) NOT NULL,
    description text,
    "default" boolean DEFAULT false NOT NULL,
    selectable boolean DEFAULT false NOT NULL,
    user_id bigint DEFAULT '0'::bigint NOT NULL,
    restrict_to_org_id bigint DEFAULT '0'::bigint NOT NULL,
    restrict_to_role_id bigint DEFAULT '0'::bigint NOT NULL,
    restrict_to_permission_flag character varying(191) DEFAULT ''::character varying NOT NULL,
    value text,
    "timestamp" bigint NOT NULL
);


--
-- Name: dashboards_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dashboards_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dashboards_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dashboards_id_seq OWNED BY public.dashboards.id;


--
-- Name: decaying_model_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.decaying_model_mappings (
    id bigint NOT NULL,
    attribute_type character varying(255) NOT NULL,
    model_id bigint NOT NULL
);


--
-- Name: decaying_model_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.decaying_model_mappings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: decaying_model_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.decaying_model_mappings_id_seq OWNED BY public.decaying_model_mappings.id;


--
-- Name: decaying_models; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.decaying_models (
    id bigint NOT NULL,
    uuid character varying(40) DEFAULT NULL::character varying,
    name character varying(255) NOT NULL,
    parameters text,
    attribute_types text,
    description text,
    org_id bigint,
    enabled boolean DEFAULT false NOT NULL,
    all_orgs boolean DEFAULT true NOT NULL,
    ref text,
    formula character varying(255) NOT NULL,
    version character varying(255) DEFAULT ''::character varying NOT NULL,
    "default" boolean DEFAULT false NOT NULL
);


--
-- Name: decaying_models_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.decaying_models_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: decaying_models_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.decaying_models_id_seq OWNED BY public.decaying_models.id;


--
-- Name: event_blocklists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_blocklists (
    id bigint NOT NULL,
    event_uuid character varying(40) NOT NULL,
    created timestamp with time zone NOT NULL,
    event_info text NOT NULL,
    comment text,
    event_orgc character varying(255) NOT NULL
);


--
-- Name: event_blocklists_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_blocklists_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_blocklists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_blocklists_id_seq OWNED BY public.event_blocklists.id;


--
-- Name: event_delegations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_delegations (
    id bigint NOT NULL,
    org_id bigint NOT NULL,
    requester_org_id bigint NOT NULL,
    event_id bigint NOT NULL,
    message text,
    distribution smallint DEFAULT '-1'::smallint NOT NULL,
    sharing_group_id bigint
);


--
-- Name: event_delegations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_delegations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_delegations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_delegations_id_seq OWNED BY public.event_delegations.id;


--
-- Name: event_graph; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_graph (
    id bigint NOT NULL,
    event_id bigint NOT NULL,
    user_id bigint NOT NULL,
    org_id bigint NOT NULL,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    network_name character varying(255) DEFAULT NULL::character varying,
    network_json text NOT NULL,
    preview_img text
);


--
-- Name: event_graph_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_graph_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_graph_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_graph_id_seq OWNED BY public.event_graph.id;


--
-- Name: event_locks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_locks (
    id bigint NOT NULL,
    event_id bigint NOT NULL,
    user_id bigint NOT NULL,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL
);


--
-- Name: event_locks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_locks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_locks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_locks_id_seq OWNED BY public.event_locks.id;


--
-- Name: event_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_reports (
    id bigint NOT NULL,
    uuid character varying(40) NOT NULL,
    event_id bigint NOT NULL,
    name character varying(255) NOT NULL,
    content text,
    distribution smallint DEFAULT '0'::smallint NOT NULL,
    sharing_group_id bigint,
    "timestamp" bigint NOT NULL,
    deleted boolean DEFAULT false NOT NULL
);


--
-- Name: event_reports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_reports_id_seq OWNED BY public.event_reports.id;


--
-- Name: event_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_tags (
    id bigint NOT NULL,
    event_id bigint NOT NULL,
    tag_id bigint NOT NULL,
    local boolean DEFAULT false NOT NULL
);


--
-- Name: event_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_tags_id_seq OWNED BY public.event_tags.id;


--
-- Name: events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events (
    id bigint NOT NULL,
    org_id bigint NOT NULL,
    date date NOT NULL,
    info text NOT NULL,
    user_id bigint NOT NULL,
    uuid character varying(40) NOT NULL,
    published boolean DEFAULT false NOT NULL,
    analysis smallint NOT NULL,
    attribute_count bigint DEFAULT '0'::bigint,
    orgc_id bigint NOT NULL,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    distribution smallint DEFAULT '0'::smallint NOT NULL,
    sharing_group_id bigint NOT NULL,
    proposal_email_lock boolean DEFAULT false NOT NULL,
    locked boolean DEFAULT false NOT NULL,
    threat_level_id bigint NOT NULL,
    publish_timestamp bigint DEFAULT '0'::bigint NOT NULL,
    sighting_timestamp bigint DEFAULT '0'::bigint NOT NULL,
    disable_correlation boolean DEFAULT false NOT NULL,
    extends_uuid character varying(40) DEFAULT ''::character varying
);


--
-- Name: events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.events_id_seq OWNED BY public.events.id;


--
-- Name: favourite_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.favourite_tags (
    id bigint NOT NULL,
    tag_id bigint NOT NULL,
    user_id bigint NOT NULL
);


--
-- Name: favourite_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.favourite_tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: favourite_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.favourite_tags_id_seq OWNED BY public.favourite_tags.id;


--
-- Name: feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feeds (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    provider character varying(255) NOT NULL,
    url character varying(255) NOT NULL,
    rules text,
    enabled boolean DEFAULT false,
    distribution smallint DEFAULT '0'::smallint NOT NULL,
    sharing_group_id bigint DEFAULT '0'::bigint NOT NULL,
    tag_id bigint DEFAULT '0'::bigint NOT NULL,
    "default" boolean DEFAULT false,
    source_format character varying(255) DEFAULT 'misp'::character varying,
    fixed_event boolean DEFAULT false NOT NULL,
    delta_merge boolean DEFAULT false NOT NULL,
    event_id bigint DEFAULT '0'::bigint NOT NULL,
    publish boolean DEFAULT false NOT NULL,
    override_ids boolean DEFAULT false NOT NULL,
    settings text,
    input_source character varying(255) DEFAULT 'network'::character varying NOT NULL,
    delete_local_file boolean DEFAULT false,
    lookup_visible boolean DEFAULT false,
    headers text,
    caching_enabled boolean DEFAULT false NOT NULL,
    force_to_ids boolean DEFAULT false NOT NULL,
    orgc_id bigint DEFAULT '0'::bigint NOT NULL
);


--
-- Name: feeds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.feeds_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: feeds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.feeds_id_seq OWNED BY public.feeds.id;


--
-- Name: fuzzy_correlate_ssdeep; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fuzzy_correlate_ssdeep (
    id bigint NOT NULL,
    chunk character varying(12) NOT NULL,
    attribute_id bigint NOT NULL
);


--
-- Name: fuzzy_correlate_ssdeep_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.fuzzy_correlate_ssdeep_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fuzzy_correlate_ssdeep_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.fuzzy_correlate_ssdeep_id_seq OWNED BY public.fuzzy_correlate_ssdeep.id;


--
-- Name: galaxies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.galaxies (
    id bigint NOT NULL,
    uuid character varying(255) NOT NULL,
    name character varying(255) DEFAULT ''::character varying NOT NULL,
    type character varying(255) NOT NULL,
    description text NOT NULL,
    version character varying(255) NOT NULL,
    icon character varying(255) DEFAULT ''::character varying NOT NULL,
    namespace character varying(255) DEFAULT 'misp'::character varying NOT NULL,
    kill_chain_order text
);


--
-- Name: galaxies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.galaxies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: galaxies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.galaxies_id_seq OWNED BY public.galaxies.id;


--
-- Name: galaxy_clusters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.galaxy_clusters (
    id bigint NOT NULL,
    uuid character varying(255) DEFAULT ''::character varying NOT NULL,
    collection_uuid character varying(255) NOT NULL,
    type character varying(255) NOT NULL,
    value text NOT NULL,
    tag_name character varying(255) DEFAULT ''::character varying NOT NULL,
    description text NOT NULL,
    galaxy_id bigint NOT NULL,
    source character varying(255) DEFAULT ''::character varying NOT NULL,
    authors text NOT NULL,
    version bigint DEFAULT '0'::bigint
);


--
-- Name: galaxy_clusters_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.galaxy_clusters_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: galaxy_clusters_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.galaxy_clusters_id_seq OWNED BY public.galaxy_clusters.id;


--
-- Name: galaxy_elements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.galaxy_elements (
    id bigint NOT NULL,
    galaxy_cluster_id bigint NOT NULL,
    key character varying(255) DEFAULT ''::character varying NOT NULL,
    value text NOT NULL
);


--
-- Name: galaxy_elements_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.galaxy_elements_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: galaxy_elements_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.galaxy_elements_id_seq OWNED BY public.galaxy_elements.id;


--
-- Name: galaxy_reference; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.galaxy_reference (
    id bigint NOT NULL,
    galaxy_cluster_id bigint NOT NULL,
    referenced_galaxy_cluster_id bigint NOT NULL,
    referenced_galaxy_cluster_uuid character varying(255) NOT NULL,
    referenced_galaxy_cluster_type text NOT NULL,
    referenced_galaxy_cluster_value text NOT NULL
);


--
-- Name: galaxy_reference_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.galaxy_reference_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: galaxy_reference_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.galaxy_reference_id_seq OWNED BY public.galaxy_reference.id;


--
-- Name: inbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.inbox (
    id bigint NOT NULL,
    uuid character varying(40) NOT NULL,
    title character varying(191) NOT NULL,
    type character varying(191) NOT NULL,
    ip character varying(191) NOT NULL,
    user_agent text,
    user_agent_sha256 character varying(64) NOT NULL,
    comment text,
    deleted boolean DEFAULT false NOT NULL,
    "timestamp" bigint NOT NULL,
    store_as_file boolean DEFAULT false NOT NULL,
    data text
);


--
-- Name: inbox_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.inbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: inbox_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.inbox_id_seq OWNED BY public.inbox.id;


--
-- Name: jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jobs (
    id bigint NOT NULL,
    worker character varying(32) NOT NULL,
    job_type character varying(32) NOT NULL,
    job_input text NOT NULL,
    status smallint DEFAULT '0'::smallint NOT NULL,
    retries bigint DEFAULT '0'::bigint NOT NULL,
    message text NOT NULL,
    progress bigint DEFAULT '0'::bigint NOT NULL,
    org_id bigint DEFAULT '0'::bigint NOT NULL,
    process_id character varying(36) DEFAULT NULL::character varying,
    date_created timestamp with time zone NOT NULL,
    date_modified timestamp with time zone NOT NULL
);


--
-- Name: jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.jobs_id_seq OWNED BY public.jobs.id;


--
-- Name: logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.logs (
    id bigint NOT NULL,
    title text,
    created timestamp with time zone NOT NULL,
    model character varying(80) NOT NULL,
    model_id bigint NOT NULL,
    action character varying(20) NOT NULL,
    user_id bigint NOT NULL,
    change text,
    email character varying(255) DEFAULT ''::character varying NOT NULL,
    org character varying(255) DEFAULT ''::character varying NOT NULL,
    description text,
    ip character varying(45) DEFAULT ''::character varying NOT NULL
);


--
-- Name: logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.logs_id_seq OWNED BY public.logs.id;


--
-- Name: news; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.news (
    id bigint NOT NULL,
    message text NOT NULL,
    title text NOT NULL,
    user_id bigint NOT NULL,
    date_created bigint NOT NULL
);


--
-- Name: news_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.news_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: news_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.news_id_seq OWNED BY public.news.id;


--
-- Name: noticelist_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.noticelist_entries (
    id bigint NOT NULL,
    noticelist_id bigint NOT NULL,
    data text NOT NULL
);


--
-- Name: noticelist_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.noticelist_entries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: noticelist_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.noticelist_entries_id_seq OWNED BY public.noticelist_entries.id;


--
-- Name: noticelists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.noticelists (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    expanded_name text NOT NULL,
    ref text,
    geographical_area character varying(255) DEFAULT NULL::character varying,
    version bigint DEFAULT '1'::bigint NOT NULL,
    enabled boolean DEFAULT false NOT NULL
);


--
-- Name: noticelists_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.noticelists_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: noticelists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.noticelists_id_seq OWNED BY public.noticelists.id;


--
-- Name: notification_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_logs (
    id bigint NOT NULL,
    org_id bigint NOT NULL,
    type character varying(255) NOT NULL,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL
);


--
-- Name: notification_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.notification_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: notification_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.notification_logs_id_seq OWNED BY public.notification_logs.id;


--
-- Name: object_references; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.object_references (
    id bigint NOT NULL,
    uuid character varying(40) DEFAULT NULL::character varying,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    object_id bigint NOT NULL,
    event_id bigint NOT NULL,
    source_uuid character varying(40) DEFAULT NULL::character varying,
    referenced_uuid character varying(40) DEFAULT NULL::character varying,
    referenced_id bigint NOT NULL,
    referenced_type bigint DEFAULT '0'::bigint NOT NULL,
    relationship_type character varying(255) DEFAULT NULL::character varying,
    comment text NOT NULL,
    deleted boolean DEFAULT false NOT NULL
);


--
-- Name: object_references_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.object_references_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: object_references_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.object_references_id_seq OWNED BY public.object_references.id;


--
-- Name: object_relationships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.object_relationships (
    id bigint NOT NULL,
    version bigint NOT NULL,
    name character varying(255) DEFAULT NULL::character varying,
    description text NOT NULL,
    format text NOT NULL
);


--
-- Name: object_relationships_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.object_relationships_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: object_relationships_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.object_relationships_id_seq OWNED BY public.object_relationships.id;


--
-- Name: object_template_elements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.object_template_elements (
    id bigint NOT NULL,
    object_template_id bigint NOT NULL,
    object_relation character varying(255) DEFAULT NULL::character varying,
    type character varying(255) DEFAULT NULL::character varying,
    "ui-priority" bigint NOT NULL,
    categories text,
    sane_default text,
    values_list text,
    description text,
    disable_correlation boolean,
    multiple boolean DEFAULT false NOT NULL
);


--
-- Name: object_template_elements_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.object_template_elements_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: object_template_elements_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.object_template_elements_id_seq OWNED BY public.object_template_elements.id;


--
-- Name: object_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.object_templates (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    org_id bigint NOT NULL,
    uuid character varying(40) DEFAULT NULL::character varying,
    name character varying(255) DEFAULT NULL::character varying,
    "meta-category" character varying(255) DEFAULT NULL::character varying,
    description text,
    version bigint NOT NULL,
    requirements text,
    fixed boolean DEFAULT false NOT NULL,
    active boolean DEFAULT false NOT NULL
);


--
-- Name: object_templates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.object_templates_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: object_templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.object_templates_id_seq OWNED BY public.object_templates.id;


--
-- Name: objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.objects (
    id bigint NOT NULL,
    name character varying(255) DEFAULT NULL::character varying,
    "meta-category" character varying(255) DEFAULT NULL::character varying,
    description text,
    template_uuid character varying(40) DEFAULT NULL::character varying,
    template_version bigint NOT NULL,
    event_id bigint NOT NULL,
    uuid character varying(40) DEFAULT NULL::character varying,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    distribution smallint DEFAULT '0'::smallint NOT NULL,
    sharing_group_id bigint,
    comment text NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    first_seen bigint,
    last_seen bigint
);


--
-- Name: objects_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.objects_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: objects_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.objects_id_seq OWNED BY public.objects.id;


--
-- Name: org_blocklists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_blocklists (
    id bigint NOT NULL,
    org_uuid character varying(40) NOT NULL,
    created timestamp with time zone NOT NULL,
    org_name character varying(255) NOT NULL,
    comment text
);


--
-- Name: org_blocklists_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.org_blocklists_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: org_blocklists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.org_blocklists_id_seq OWNED BY public.org_blocklists.id;


--
-- Name: organisations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organisations (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    date_created timestamp with time zone NOT NULL,
    date_modified timestamp with time zone NOT NULL,
    description text,
    type character varying(255) DEFAULT NULL::character varying,
    nationality character varying(255) DEFAULT NULL::character varying,
    sector character varying(255) DEFAULT NULL::character varying,
    created_by bigint DEFAULT '0'::bigint NOT NULL,
    uuid character varying(40) DEFAULT NULL::character varying,
    contacts text,
    local boolean DEFAULT false NOT NULL,
    restricted_to_domain text,
    landingpage text
);


--
-- Name: organisations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.organisations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: organisations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.organisations_id_seq OWNED BY public.organisations.id;


--
-- Name: posts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.posts (
    id bigint NOT NULL,
    date_created timestamp with time zone NOT NULL,
    date_modified timestamp with time zone NOT NULL,
    user_id bigint NOT NULL,
    contents text NOT NULL,
    post_id bigint DEFAULT '0'::bigint NOT NULL,
    thread_id bigint DEFAULT '0'::bigint NOT NULL
);


--
-- Name: posts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.posts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: posts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.posts_id_seq OWNED BY public.posts.id;


--
-- Name: regexp; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.regexp (
    id bigint NOT NULL,
    regexp character varying(255) NOT NULL,
    replacement character varying(255) NOT NULL,
    type character varying(100) DEFAULT 'ALL'::character varying NOT NULL
);


--
-- Name: regexp_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.regexp_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: regexp_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.regexp_id_seq OWNED BY public.regexp.id;


--
-- Name: rest_client_histories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rest_client_histories (
    id bigint NOT NULL,
    org_id bigint NOT NULL,
    user_id bigint NOT NULL,
    headers text,
    body text,
    url text,
    http_method character varying(255) DEFAULT NULL::character varying,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    use_full_path boolean DEFAULT false,
    show_result boolean DEFAULT false,
    skip_ssl boolean DEFAULT false,
    outcome bigint NOT NULL,
    bookmark boolean DEFAULT false NOT NULL,
    bookmark_name character varying(255) DEFAULT ''::character varying
);


--
-- Name: rest_client_histories_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.rest_client_histories_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: rest_client_histories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.rest_client_histories_id_seq OWNED BY public.rest_client_histories.id;


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    id bigint NOT NULL,
    name character varying(100) NOT NULL,
    created timestamp with time zone,
    modified timestamp with time zone,
    perm_add boolean,
    perm_modify boolean,
    perm_modify_org boolean,
    perm_publish boolean,
    perm_delegate boolean DEFAULT false NOT NULL,
    perm_sync boolean,
    perm_admin boolean,
    perm_audit boolean,
    perm_full boolean,
    perm_auth boolean DEFAULT false NOT NULL,
    perm_site_admin boolean DEFAULT false NOT NULL,
    perm_regexp_access boolean DEFAULT false NOT NULL,
    perm_tagger boolean DEFAULT false NOT NULL,
    perm_template boolean DEFAULT false NOT NULL,
    perm_sharing_group boolean DEFAULT false NOT NULL,
    perm_tag_editor boolean DEFAULT false NOT NULL,
    perm_sighting boolean DEFAULT false NOT NULL,
    perm_object_template boolean DEFAULT false NOT NULL,
    default_role boolean DEFAULT false NOT NULL,
    memory_limit character varying(255) DEFAULT ''::character varying,
    max_execution_time character varying(255) DEFAULT ''::character varying,
    restricted_to_site_admin boolean DEFAULT false NOT NULL,
    perm_publish_zmq boolean DEFAULT false NOT NULL,
    perm_publish_kafka boolean DEFAULT false NOT NULL,
    perm_decaying boolean DEFAULT false NOT NULL,
    enforce_rate_limit boolean DEFAULT false NOT NULL,
    rate_limit_count bigint DEFAULT '0'::bigint NOT NULL
);


--
-- Name: roles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.roles_id_seq OWNED BY public.roles.id;


--
-- Name: servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.servers (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    url character varying(255) NOT NULL,
    authkey character varying(40) NOT NULL,
    org_id bigint NOT NULL,
    push boolean NOT NULL,
    pull boolean NOT NULL,
    push_sightings boolean DEFAULT false NOT NULL,
    lastpulledid bigint,
    lastpushedid bigint,
    organization character varying(10) DEFAULT NULL::character varying,
    remote_org_id bigint NOT NULL,
    publish_without_email boolean DEFAULT false NOT NULL,
    unpublish_event boolean DEFAULT false NOT NULL,
    self_signed boolean NOT NULL,
    pull_rules text NOT NULL,
    push_rules text NOT NULL,
    cert_file character varying(255) DEFAULT NULL::character varying,
    client_cert_file character varying(255) DEFAULT NULL::character varying,
    internal boolean DEFAULT false NOT NULL,
    skip_proxy boolean DEFAULT false NOT NULL,
    caching_enabled boolean DEFAULT false NOT NULL,
    priority bigint DEFAULT '0'::bigint NOT NULL
);


--
-- Name: servers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.servers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: servers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.servers_id_seq OWNED BY public.servers.id;


--
-- Name: shadow_attribute_correlations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shadow_attribute_correlations (
    id bigint NOT NULL,
    org_id bigint NOT NULL,
    value text NOT NULL,
    distribution smallint NOT NULL,
    a_distribution smallint NOT NULL,
    sharing_group_id bigint,
    a_sharing_group_id bigint,
    attribute_id bigint NOT NULL,
    "1_shadow_attribute_id" bigint NOT NULL,
    event_id bigint NOT NULL,
    "1_event_id" bigint NOT NULL,
    info text NOT NULL
);


--
-- Name: shadow_attribute_correlations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.shadow_attribute_correlations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: shadow_attribute_correlations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.shadow_attribute_correlations_id_seq OWNED BY public.shadow_attribute_correlations.id;


--
-- Name: shadow_attributes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shadow_attributes (
    id bigint NOT NULL,
    old_id bigint DEFAULT '0'::bigint,
    event_id bigint NOT NULL,
    type character varying(100) NOT NULL,
    category character varying(255) NOT NULL,
    value1 text,
    to_ids boolean DEFAULT true NOT NULL,
    uuid character varying(40) NOT NULL,
    value2 text,
    org_id bigint NOT NULL,
    email character varying(255) DEFAULT NULL::character varying,
    event_org_id bigint NOT NULL,
    comment text NOT NULL,
    event_uuid character varying(40) NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    proposal_to_delete boolean DEFAULT false NOT NULL,
    disable_correlation boolean DEFAULT false NOT NULL,
    first_seen bigint,
    last_seen bigint
);


--
-- Name: shadow_attributes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.shadow_attributes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: shadow_attributes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.shadow_attributes_id_seq OWNED BY public.shadow_attributes.id;


--
-- Name: sharing_group_orgs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sharing_group_orgs (
    id bigint NOT NULL,
    sharing_group_id bigint NOT NULL,
    org_id bigint NOT NULL,
    extend boolean DEFAULT false NOT NULL
);


--
-- Name: sharing_group_orgs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sharing_group_orgs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sharing_group_orgs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sharing_group_orgs_id_seq OWNED BY public.sharing_group_orgs.id;


--
-- Name: sharing_group_servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sharing_group_servers (
    id bigint NOT NULL,
    sharing_group_id bigint NOT NULL,
    server_id bigint NOT NULL,
    all_orgs boolean NOT NULL
);


--
-- Name: sharing_group_servers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sharing_group_servers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sharing_group_servers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sharing_group_servers_id_seq OWNED BY public.sharing_group_servers.id;


--
-- Name: sharing_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sharing_groups (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    releasability text NOT NULL,
    description text NOT NULL,
    uuid character varying(40) NOT NULL,
    organisation_uuid character varying(40) NOT NULL,
    org_id bigint NOT NULL,
    sync_user_id bigint DEFAULT '0'::bigint NOT NULL,
    active boolean NOT NULL,
    created timestamp with time zone NOT NULL,
    modified timestamp with time zone NOT NULL,
    local boolean NOT NULL,
    roaming boolean DEFAULT false NOT NULL
);


--
-- Name: sharing_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sharing_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sharing_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sharing_groups_id_seq OWNED BY public.sharing_groups.id;


--
-- Name: sightingdb_orgs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sightingdb_orgs (
    id bigint NOT NULL,
    sightingdb_id bigint NOT NULL,
    org_id bigint NOT NULL
);


--
-- Name: sightingdb_orgs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sightingdb_orgs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sightingdb_orgs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sightingdb_orgs_id_seq OWNED BY public.sightingdb_orgs.id;


--
-- Name: sightingdbs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sightingdbs (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    owner character varying(255) DEFAULT ''::character varying,
    host character varying(255) DEFAULT 'http://localhost'::character varying,
    port bigint DEFAULT '9999'::bigint,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    skip_proxy boolean DEFAULT false NOT NULL,
    ssl_skip_verification boolean DEFAULT false NOT NULL,
    namespace character varying(255) DEFAULT ''::character varying
);


--
-- Name: sightingdbs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sightingdbs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sightingdbs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sightingdbs_id_seq OWNED BY public.sightingdbs.id;


--
-- Name: sightings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sightings (
    id bigint NOT NULL,
    attribute_id bigint NOT NULL,
    event_id bigint NOT NULL,
    org_id bigint NOT NULL,
    date_sighting bigint NOT NULL,
    uuid character varying(255) DEFAULT ''::character varying,
    source character varying(255) DEFAULT ''::character varying,
    type bigint DEFAULT '0'::bigint
);


--
-- Name: sightings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sightings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sightings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sightings_id_seq OWNED BY public.sightings.id;


--
-- Name: tag_collection_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tag_collection_tags (
    id bigint NOT NULL,
    tag_collection_id bigint NOT NULL,
    tag_id bigint NOT NULL
);


--
-- Name: tag_collection_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tag_collection_tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tag_collection_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tag_collection_tags_id_seq OWNED BY public.tag_collection_tags.id;


--
-- Name: tag_collections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tag_collections (
    id bigint NOT NULL,
    uuid character varying(40) DEFAULT NULL::character varying,
    user_id bigint NOT NULL,
    org_id bigint NOT NULL,
    name character varying(255) NOT NULL,
    description text NOT NULL,
    all_orgs boolean DEFAULT false NOT NULL
);


--
-- Name: tag_collections_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tag_collections_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tag_collections_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tag_collections_id_seq OWNED BY public.tag_collections.id;


--
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tags (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    colour character varying(7) NOT NULL,
    exportable boolean NOT NULL,
    org_id bigint DEFAULT '0'::bigint NOT NULL,
    user_id bigint DEFAULT '0'::bigint NOT NULL,
    hide_tag boolean DEFAULT false NOT NULL,
    numerical_value bigint
);


--
-- Name: tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tags_id_seq OWNED BY public.tags.id;


--
-- Name: tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tasks (
    id bigint NOT NULL,
    type character varying(100) NOT NULL,
    timer bigint NOT NULL,
    scheduled_time character varying(8) DEFAULT '6:00'::character varying NOT NULL,
    process_id character varying(32) DEFAULT NULL::character varying,
    description character varying(255) NOT NULL,
    next_execution_time bigint NOT NULL,
    message character varying(255) NOT NULL
);


--
-- Name: tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tasks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tasks_id_seq OWNED BY public.tasks.id;


--
-- Name: taxonomies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.taxonomies (
    id bigint NOT NULL,
    namespace character varying(255) NOT NULL,
    description text NOT NULL,
    version bigint NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    exclusive boolean DEFAULT false,
    required boolean DEFAULT false NOT NULL
);


--
-- Name: taxonomies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.taxonomies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: taxonomies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.taxonomies_id_seq OWNED BY public.taxonomies.id;


--
-- Name: taxonomy_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.taxonomy_entries (
    id bigint NOT NULL,
    taxonomy_predicate_id bigint NOT NULL,
    value text NOT NULL,
    expanded text,
    colour character varying(7) DEFAULT NULL::character varying,
    description text,
    numerical_value bigint
);


--
-- Name: taxonomy_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.taxonomy_entries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: taxonomy_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.taxonomy_entries_id_seq OWNED BY public.taxonomy_entries.id;


--
-- Name: taxonomy_predicates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.taxonomy_predicates (
    id bigint NOT NULL,
    taxonomy_id bigint NOT NULL,
    value text NOT NULL,
    expanded text,
    colour character varying(7) DEFAULT NULL::character varying,
    description text,
    exclusive boolean DEFAULT false,
    numerical_value bigint
);


--
-- Name: taxonomy_predicates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.taxonomy_predicates_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: taxonomy_predicates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.taxonomy_predicates_id_seq OWNED BY public.taxonomy_predicates.id;


--
-- Name: template_element_attributes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.template_element_attributes (
    id bigint NOT NULL,
    template_element_id bigint NOT NULL,
    name character varying(255) NOT NULL,
    description text NOT NULL,
    to_ids boolean DEFAULT true NOT NULL,
    category character varying(255) NOT NULL,
    complex boolean NOT NULL,
    type character varying(255) NOT NULL,
    mandatory boolean NOT NULL,
    batch boolean NOT NULL
);


--
-- Name: template_element_attributes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.template_element_attributes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: template_element_attributes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.template_element_attributes_id_seq OWNED BY public.template_element_attributes.id;


--
-- Name: template_element_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.template_element_files (
    id bigint NOT NULL,
    template_element_id bigint NOT NULL,
    name character varying(255) NOT NULL,
    description text NOT NULL,
    category character varying(255) NOT NULL,
    malware boolean NOT NULL,
    mandatory boolean NOT NULL,
    batch boolean NOT NULL
);


--
-- Name: template_element_files_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.template_element_files_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: template_element_files_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.template_element_files_id_seq OWNED BY public.template_element_files.id;


--
-- Name: template_element_texts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.template_element_texts (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    template_element_id bigint NOT NULL,
    text text NOT NULL
);


--
-- Name: template_element_texts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.template_element_texts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: template_element_texts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.template_element_texts_id_seq OWNED BY public.template_element_texts.id;


--
-- Name: template_elements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.template_elements (
    id bigint NOT NULL,
    template_id bigint NOT NULL,
    "position" bigint NOT NULL,
    element_definition character varying(255) NOT NULL
);


--
-- Name: template_elements_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.template_elements_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: template_elements_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.template_elements_id_seq OWNED BY public.template_elements.id;


--
-- Name: template_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.template_tags (
    id bigint NOT NULL,
    template_id bigint NOT NULL,
    tag_id bigint NOT NULL
);


--
-- Name: template_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.template_tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: template_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.template_tags_id_seq OWNED BY public.template_tags.id;


--
-- Name: templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.templates (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255) NOT NULL,
    org character varying(255) NOT NULL,
    share boolean NOT NULL
);


--
-- Name: templates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.templates_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.templates_id_seq OWNED BY public.templates.id;


--
-- Name: threads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threads (
    id bigint NOT NULL,
    date_created timestamp with time zone NOT NULL,
    date_modified timestamp with time zone NOT NULL,
    distribution smallint NOT NULL,
    user_id bigint NOT NULL,
    post_count bigint NOT NULL,
    event_id bigint NOT NULL,
    title character varying(255) NOT NULL,
    org_id bigint NOT NULL,
    sharing_group_id bigint NOT NULL
);


--
-- Name: threads_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threads_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threads_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threads_id_seq OWNED BY public.threads.id;


--
-- Name: threat_levels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_levels (
    id bigint NOT NULL,
    name character varying(50) NOT NULL,
    description character varying(255) DEFAULT NULL::character varying,
    form_description character varying(255) NOT NULL
);


--
-- Name: threat_levels_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_levels_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_levels_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_levels_id_seq OWNED BY public.threat_levels.id;


--
-- Name: user_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_settings (
    id bigint NOT NULL,
    setting character varying(255) NOT NULL,
    value text NOT NULL,
    user_id bigint NOT NULL,
    "timestamp" bigint NOT NULL
);


--
-- Name: user_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_settings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_settings_id_seq OWNED BY public.user_settings.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    password character varying(255) NOT NULL,
    org_id bigint NOT NULL,
    server_id bigint DEFAULT '0'::bigint NOT NULL,
    email character varying(255) NOT NULL,
    autoalert boolean DEFAULT false NOT NULL,
    authkey character varying(40) DEFAULT NULL::character varying,
    invited_by bigint DEFAULT '0'::bigint NOT NULL,
    gpgkey text,
    certif_public text,
    nids_sid bigint DEFAULT '0'::bigint NOT NULL,
    termsaccepted boolean DEFAULT false NOT NULL,
    newsread bigint DEFAULT '0'::bigint,
    role_id bigint DEFAULT '0'::bigint NOT NULL,
    change_pw smallint DEFAULT '0'::smallint NOT NULL,
    contactalert boolean DEFAULT false NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    expiration timestamp with time zone,
    current_login bigint DEFAULT '0'::bigint,
    last_login bigint DEFAULT '0'::bigint,
    force_logout boolean DEFAULT false NOT NULL,
    date_created bigint,
    date_modified bigint
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: warninglist_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.warninglist_entries (
    id bigint NOT NULL,
    value text NOT NULL,
    warninglist_id bigint NOT NULL
);


--
-- Name: warninglist_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.warninglist_entries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: warninglist_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.warninglist_entries_id_seq OWNED BY public.warninglist_entries.id;


--
-- Name: warninglist_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.warninglist_types (
    id bigint NOT NULL,
    type character varying(255) NOT NULL,
    warninglist_id bigint NOT NULL
);


--
-- Name: warninglist_types_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.warninglist_types_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: warninglist_types_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.warninglist_types_id_seq OWNED BY public.warninglist_types.id;


--
-- Name: warninglists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.warninglists (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(255) DEFAULT 'string'::character varying NOT NULL,
    description text NOT NULL,
    version bigint DEFAULT '1'::bigint NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    warninglist_entry_count bigint DEFAULT '0'::bigint NOT NULL
);


--
-- Name: warninglists_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.warninglists_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: warninglists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.warninglists_id_seq OWNED BY public.warninglists.id;


--
-- Name: admin_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_settings ALTER COLUMN id SET DEFAULT nextval('public.admin_settings_id_seq'::regclass);


--
-- Name: allowedlist id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.allowedlist ALTER COLUMN id SET DEFAULT nextval('public.allowedlist_id_seq'::regclass);


--
-- Name: attachment_scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachment_scans ALTER COLUMN id SET DEFAULT nextval('public.attachment_scans_id_seq'::regclass);


--
-- Name: attribute_tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_tags ALTER COLUMN id SET DEFAULT nextval('public.attribute_tags_id_seq'::regclass);


--
-- Name: attributes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attributes ALTER COLUMN id SET DEFAULT nextval('public.attributes_id_seq'::regclass);


--
-- Name: auth_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_keys ALTER COLUMN id SET DEFAULT nextval('public.auth_keys_id_seq'::regclass);


--
-- Name: correlations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlations ALTER COLUMN id SET DEFAULT nextval('public.correlations_id_seq'::regclass);


--
-- Name: dashboards id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dashboards ALTER COLUMN id SET DEFAULT nextval('public.dashboards_id_seq'::regclass);


--
-- Name: decaying_model_mappings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.decaying_model_mappings ALTER COLUMN id SET DEFAULT nextval('public.decaying_model_mappings_id_seq'::regclass);


--
-- Name: decaying_models id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.decaying_models ALTER COLUMN id SET DEFAULT nextval('public.decaying_models_id_seq'::regclass);


--
-- Name: event_blocklists id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_blocklists ALTER COLUMN id SET DEFAULT nextval('public.event_blocklists_id_seq'::regclass);


--
-- Name: event_delegations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_delegations ALTER COLUMN id SET DEFAULT nextval('public.event_delegations_id_seq'::regclass);


--
-- Name: event_graph id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_graph ALTER COLUMN id SET DEFAULT nextval('public.event_graph_id_seq'::regclass);


--
-- Name: event_locks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_locks ALTER COLUMN id SET DEFAULT nextval('public.event_locks_id_seq'::regclass);


--
-- Name: event_reports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_reports ALTER COLUMN id SET DEFAULT nextval('public.event_reports_id_seq'::regclass);


--
-- Name: event_tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_tags ALTER COLUMN id SET DEFAULT nextval('public.event_tags_id_seq'::regclass);


--
-- Name: events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ALTER COLUMN id SET DEFAULT nextval('public.events_id_seq'::regclass);


--
-- Name: favourite_tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.favourite_tags ALTER COLUMN id SET DEFAULT nextval('public.favourite_tags_id_seq'::regclass);


--
-- Name: feeds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feeds ALTER COLUMN id SET DEFAULT nextval('public.feeds_id_seq'::regclass);


--
-- Name: fuzzy_correlate_ssdeep id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fuzzy_correlate_ssdeep ALTER COLUMN id SET DEFAULT nextval('public.fuzzy_correlate_ssdeep_id_seq'::regclass);


--
-- Name: galaxies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxies ALTER COLUMN id SET DEFAULT nextval('public.galaxies_id_seq'::regclass);


--
-- Name: galaxy_clusters id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxy_clusters ALTER COLUMN id SET DEFAULT nextval('public.galaxy_clusters_id_seq'::regclass);


--
-- Name: galaxy_elements id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxy_elements ALTER COLUMN id SET DEFAULT nextval('public.galaxy_elements_id_seq'::regclass);


--
-- Name: galaxy_reference id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxy_reference ALTER COLUMN id SET DEFAULT nextval('public.galaxy_reference_id_seq'::regclass);


--
-- Name: inbox id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbox ALTER COLUMN id SET DEFAULT nextval('public.inbox_id_seq'::regclass);


--
-- Name: jobs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs ALTER COLUMN id SET DEFAULT nextval('public.jobs_id_seq'::regclass);


--
-- Name: logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.logs ALTER COLUMN id SET DEFAULT nextval('public.logs_id_seq'::regclass);


--
-- Name: news id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.news ALTER COLUMN id SET DEFAULT nextval('public.news_id_seq'::regclass);


--
-- Name: noticelist_entries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.noticelist_entries ALTER COLUMN id SET DEFAULT nextval('public.noticelist_entries_id_seq'::regclass);


--
-- Name: noticelists id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.noticelists ALTER COLUMN id SET DEFAULT nextval('public.noticelists_id_seq'::regclass);


--
-- Name: notification_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_logs ALTER COLUMN id SET DEFAULT nextval('public.notification_logs_id_seq'::regclass);


--
-- Name: object_references id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_references ALTER COLUMN id SET DEFAULT nextval('public.object_references_id_seq'::regclass);


--
-- Name: object_relationships id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_relationships ALTER COLUMN id SET DEFAULT nextval('public.object_relationships_id_seq'::regclass);


--
-- Name: object_template_elements id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_template_elements ALTER COLUMN id SET DEFAULT nextval('public.object_template_elements_id_seq'::regclass);


--
-- Name: object_templates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_templates ALTER COLUMN id SET DEFAULT nextval('public.object_templates_id_seq'::regclass);


--
-- Name: objects id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.objects ALTER COLUMN id SET DEFAULT nextval('public.objects_id_seq'::regclass);


--
-- Name: org_blocklists id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_blocklists ALTER COLUMN id SET DEFAULT nextval('public.org_blocklists_id_seq'::regclass);


--
-- Name: organisations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organisations ALTER COLUMN id SET DEFAULT nextval('public.organisations_id_seq'::regclass);


--
-- Name: posts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posts ALTER COLUMN id SET DEFAULT nextval('public.posts_id_seq'::regclass);


--
-- Name: regexp id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.regexp ALTER COLUMN id SET DEFAULT nextval('public.regexp_id_seq'::regclass);


--
-- Name: rest_client_histories id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rest_client_histories ALTER COLUMN id SET DEFAULT nextval('public.rest_client_histories_id_seq'::regclass);


--
-- Name: roles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles ALTER COLUMN id SET DEFAULT nextval('public.roles_id_seq'::regclass);


--
-- Name: servers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.servers ALTER COLUMN id SET DEFAULT nextval('public.servers_id_seq'::regclass);


--
-- Name: shadow_attribute_correlations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shadow_attribute_correlations ALTER COLUMN id SET DEFAULT nextval('public.shadow_attribute_correlations_id_seq'::regclass);


--
-- Name: shadow_attributes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shadow_attributes ALTER COLUMN id SET DEFAULT nextval('public.shadow_attributes_id_seq'::regclass);


--
-- Name: sharing_group_orgs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sharing_group_orgs ALTER COLUMN id SET DEFAULT nextval('public.sharing_group_orgs_id_seq'::regclass);


--
-- Name: sharing_group_servers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sharing_group_servers ALTER COLUMN id SET DEFAULT nextval('public.sharing_group_servers_id_seq'::regclass);


--
-- Name: sharing_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sharing_groups ALTER COLUMN id SET DEFAULT nextval('public.sharing_groups_id_seq'::regclass);


--
-- Name: sightingdb_orgs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sightingdb_orgs ALTER COLUMN id SET DEFAULT nextval('public.sightingdb_orgs_id_seq'::regclass);


--
-- Name: sightingdbs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sightingdbs ALTER COLUMN id SET DEFAULT nextval('public.sightingdbs_id_seq'::regclass);


--
-- Name: sightings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sightings ALTER COLUMN id SET DEFAULT nextval('public.sightings_id_seq'::regclass);


--
-- Name: tag_collection_tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tag_collection_tags ALTER COLUMN id SET DEFAULT nextval('public.tag_collection_tags_id_seq'::regclass);


--
-- Name: tag_collections id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tag_collections ALTER COLUMN id SET DEFAULT nextval('public.tag_collections_id_seq'::regclass);


--
-- Name: tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags ALTER COLUMN id SET DEFAULT nextval('public.tags_id_seq'::regclass);


--
-- Name: tasks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks ALTER COLUMN id SET DEFAULT nextval('public.tasks_id_seq'::regclass);


--
-- Name: taxonomies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.taxonomies ALTER COLUMN id SET DEFAULT nextval('public.taxonomies_id_seq'::regclass);


--
-- Name: taxonomy_entries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.taxonomy_entries ALTER COLUMN id SET DEFAULT nextval('public.taxonomy_entries_id_seq'::regclass);


--
-- Name: taxonomy_predicates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.taxonomy_predicates ALTER COLUMN id SET DEFAULT nextval('public.taxonomy_predicates_id_seq'::regclass);


--
-- Name: template_element_attributes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_element_attributes ALTER COLUMN id SET DEFAULT nextval('public.template_element_attributes_id_seq'::regclass);


--
-- Name: template_element_files id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_element_files ALTER COLUMN id SET DEFAULT nextval('public.template_element_files_id_seq'::regclass);


--
-- Name: template_element_texts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_element_texts ALTER COLUMN id SET DEFAULT nextval('public.template_element_texts_id_seq'::regclass);


--
-- Name: template_elements id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_elements ALTER COLUMN id SET DEFAULT nextval('public.template_elements_id_seq'::regclass);


--
-- Name: template_tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_tags ALTER COLUMN id SET DEFAULT nextval('public.template_tags_id_seq'::regclass);


--
-- Name: templates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.templates ALTER COLUMN id SET DEFAULT nextval('public.templates_id_seq'::regclass);


--
-- Name: threads id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threads ALTER COLUMN id SET DEFAULT nextval('public.threads_id_seq'::regclass);


--
-- Name: threat_levels id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_levels ALTER COLUMN id SET DEFAULT nextval('public.threat_levels_id_seq'::regclass);


--
-- Name: user_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings ALTER COLUMN id SET DEFAULT nextval('public.user_settings_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: warninglist_entries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.warninglist_entries ALTER COLUMN id SET DEFAULT nextval('public.warninglist_entries_id_seq'::regclass);


--
-- Name: warninglist_types id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.warninglist_types ALTER COLUMN id SET DEFAULT nextval('public.warninglist_types_id_seq'::regclass);


--
-- Name: warninglists id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.warninglists ALTER COLUMN id SET DEFAULT nextval('public.warninglists_id_seq'::regclass);


--
-- Data for Name: admin_settings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.admin_settings (id, setting, value) FROM stdin;
1	db_version	61
2	fix_login	2023-05-08 09:41:17
3	default_role	3
\.


--
-- Data for Name: allowedlist; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.allowedlist (id, name) FROM stdin;
\.


--
-- Data for Name: attachment_scans; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attachment_scans (id, type, attribute_id, infected, malware_name, "timestamp") FROM stdin;
\.


--
-- Data for Name: attribute_tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attribute_tags (id, attribute_id, event_id, tag_id, local) FROM stdin;
\.


--
-- Data for Name: attributes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attributes (id, event_id, object_id, object_relation, category, type, value1, value2, to_ids, uuid, "timestamp", distribution, sharing_group_id, comment, deleted, disable_correlation, first_seen, last_seen) FROM stdin;
\.


--
-- Data for Name: auth_keys; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.auth_keys (id, uuid, authkey, authkey_start, authkey_end, created, expiration, user_id, comment, allowed_ips, unique_ips) FROM stdin;
\.


--
-- Data for Name: bruteforces; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.bruteforces (ip, username, expire) FROM stdin;
\.


--
-- Data for Name: cake_sessions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.cake_sessions (id, data, expires) FROM stdin;
\.


--
-- Data for Name: correlations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.correlations (id, value, "1_event_id", "1_attribute_id", event_id, attribute_id, org_id, distribution, a_distribution, sharing_group_id, a_sharing_group_id) FROM stdin;
\.


--
-- Data for Name: dashboards; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.dashboards (id, uuid, name, description, "default", selectable, user_id, restrict_to_org_id, restrict_to_role_id, restrict_to_permission_flag, value, "timestamp") FROM stdin;
\.


--
-- Data for Name: decaying_model_mappings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.decaying_model_mappings (id, attribute_type, model_id) FROM stdin;
\.


--
-- Data for Name: decaying_models; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.decaying_models (id, uuid, name, parameters, attribute_types, description, org_id, enabled, all_orgs, ref, formula, version, "default") FROM stdin;
\.


--
-- Data for Name: event_blocklists; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_blocklists (id, event_uuid, created, event_info, comment, event_orgc) FROM stdin;
\.


--
-- Data for Name: event_delegations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_delegations (id, org_id, requester_org_id, event_id, message, distribution, sharing_group_id) FROM stdin;
\.


--
-- Data for Name: event_graph; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_graph (id, event_id, user_id, org_id, "timestamp", network_name, network_json, preview_img) FROM stdin;
\.


--
-- Data for Name: event_locks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_locks (id, event_id, user_id, "timestamp") FROM stdin;
\.


--
-- Data for Name: event_reports; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_reports (id, uuid, event_id, name, content, distribution, sharing_group_id, "timestamp", deleted) FROM stdin;
\.


--
-- Data for Name: event_tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_tags (id, event_id, tag_id, local) FROM stdin;
\.


--
-- Data for Name: events; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.events (id, org_id, date, info, user_id, uuid, published, analysis, attribute_count, orgc_id, "timestamp", distribution, sharing_group_id, proposal_email_lock, locked, threat_level_id, publish_timestamp, sighting_timestamp, disable_correlation, extends_uuid) FROM stdin;
\.


--
-- Data for Name: favourite_tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.favourite_tags (id, tag_id, user_id) FROM stdin;
\.


--
-- Data for Name: feeds; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.feeds (id, name, provider, url, rules, enabled, distribution, sharing_group_id, tag_id, "default", source_format, fixed_event, delta_merge, event_id, publish, override_ids, settings, input_source, delete_local_file, lookup_visible, headers, caching_enabled, force_to_ids, orgc_id) FROM stdin;
1	CIRCL OSINT Feed	CIRCL	https://www.circl.lu/doc/misp/feed-osint	\N	f	3	0	0	t	misp	f	f	0	f	f	\N	network	f	f	\N	f	f	0
2	The Botvrij.eu Data	Botvrij.eu	https://www.botvrij.eu/data/feed-osint	\N	f	3	0	0	t	misp	f	f	0	f	f	\N	network	f	f	\N	f	f	0
\.


--
-- Data for Name: fuzzy_correlate_ssdeep; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.fuzzy_correlate_ssdeep (id, chunk, attribute_id) FROM stdin;
\.


--
-- Data for Name: galaxies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.galaxies (id, uuid, name, type, description, version, icon, namespace, kill_chain_order) FROM stdin;
\.


--
-- Data for Name: galaxy_clusters; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.galaxy_clusters (id, uuid, collection_uuid, type, value, tag_name, description, galaxy_id, source, authors, version) FROM stdin;
\.


--
-- Data for Name: galaxy_elements; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.galaxy_elements (id, galaxy_cluster_id, key, value) FROM stdin;
\.


--
-- Data for Name: galaxy_reference; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.galaxy_reference (id, galaxy_cluster_id, referenced_galaxy_cluster_id, referenced_galaxy_cluster_uuid, referenced_galaxy_cluster_type, referenced_galaxy_cluster_value) FROM stdin;
\.


--
-- Data for Name: inbox; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.inbox (id, uuid, title, type, ip, user_agent, user_agent_sha256, comment, deleted, "timestamp", store_as_file, data) FROM stdin;
\.


--
-- Data for Name: jobs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.jobs (id, worker, job_type, job_input, status, retries, message, progress, org_id, process_id, date_created, date_modified) FROM stdin;
\.


--
-- Data for Name: logs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.logs (id, title, created, model, model_id, action, user_id, change, email, org, description, ip) FROM stdin;
\.


--
-- Data for Name: news; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.news (id, message, title, user_id, date_created) FROM stdin;
\.


--
-- Data for Name: noticelist_entries; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.noticelist_entries (id, noticelist_id, data) FROM stdin;
\.


--
-- Data for Name: noticelists; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.noticelists (id, name, expanded_name, ref, geographical_area, version, enabled) FROM stdin;
\.


--
-- Data for Name: notification_logs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.notification_logs (id, org_id, type, "timestamp") FROM stdin;
\.


--
-- Data for Name: object_references; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.object_references (id, uuid, "timestamp", object_id, event_id, source_uuid, referenced_uuid, referenced_id, referenced_type, relationship_type, comment, deleted) FROM stdin;
\.


--
-- Data for Name: object_relationships; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.object_relationships (id, version, name, description, format) FROM stdin;
\.


--
-- Data for Name: object_template_elements; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.object_template_elements (id, object_template_id, object_relation, type, "ui-priority", categories, sane_default, values_list, description, disable_correlation, multiple) FROM stdin;
\.


--
-- Data for Name: object_templates; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.object_templates (id, user_id, org_id, uuid, name, "meta-category", description, version, requirements, fixed, active) FROM stdin;
\.


--
-- Data for Name: objects; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.objects (id, name, "meta-category", description, template_uuid, template_version, event_id, uuid, "timestamp", distribution, sharing_group_id, comment, deleted, first_seen, last_seen) FROM stdin;
\.


--
-- Data for Name: org_blocklists; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.org_blocklists (id, org_uuid, created, org_name, comment) FROM stdin;
1	58d38339-7b24-4386-b4b4-4c0f950d210f	2023-05-08 09:41:17+00	Setec Astrononomy	default example
2	58d38326-eda8-443a-9fa8-4e12950d210f	2023-05-08 09:41:17+00	Acme Finance	default example
\.


--
-- Data for Name: organisations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.organisations (id, name, date_created, date_modified, description, type, nationality, sector, created_by, uuid, contacts, local, restricted_to_domain, landingpage) FROM stdin;
\.


--
-- Data for Name: posts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.posts (id, date_created, date_modified, user_id, contents, post_id, thread_id) FROM stdin;
\.


--
-- Data for Name: regexp; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.regexp (id, regexp, replacement, type) FROM stdin;
1	/.:.ProgramData./i	%ALLUSERSPROFILE%\\\\	ALL
2	/.:.Documents and Settings.All Users./i	%ALLUSERSPROFILE%\\\\	ALL
3	/.:.Program Files.Common Files./i	%COMMONPROGRAMFILES%\\\\	ALL
4	/.:.Program Files (x86).Common Files./i	%COMMONPROGRAMFILES(x86)%\\\\	ALL
5	/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i	%TEMP%\\\\	ALL
6	/.:.ProgramData./i	%PROGRAMDATA%\\\\	ALL
7	/.:.Program Files./i	%PROGRAMFILES%\\\\	ALL
8	/.:.Program Files (x86)./i	%PROGRAMFILES(X86)%\\\\	ALL
9	/.:.Users.Public./i	%PUBLIC%\\\\	ALL
10	/.:.Documents and Settings\\\\(.*?)\\\\Local Settings.Temp./i	%TEMP%\\\\	ALL
11	/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i	%TEMP%\\\\	ALL
12	/.:.Users\\\\(.*?)\\\\AppData.Local./i	%LOCALAPPDATA%\\\\	ALL
13	/.:.Users\\\\(.*?)\\\\AppData.Roaming./i	%APPDATA%\\\\	ALL
14	/.:.Users\\\\(.*?)\\\\Application Data./i	%APPDATA%\\\\	ALL
15	/.:.Windows\\\\(.*?)\\\\Application Data./i	%APPDATA%\\\\	ALL
16	/.:.Users\\\\(.*?)\\\\/i	%USERPROFILE%\\\\	ALL
17	/.:.DOCUME~1.\\\\(.*?)\\\\/i	%USERPROFILE%\\\\	ALL
18	/.:.Documents and Settings\\\\(.*?)\\\\/i	%USERPROFILE%\\\\	ALL
19	/.:.Windows./i	%WINDIR%\\\\	ALL
20	/.:.Windows./i	%WINDIR%\\\\	ALL
21	/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}/i	HKCU	ALL
22	/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}/i	HKCU	ALL
23	/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}/i	HKCU	ALL
24	/.REGISTRY.MACHINE./i	HKLM\\\\	ALL
25	/.Registry.Machine./i	HKLM\\\\	ALL
26	/%USERPROFILE%.Application Data.Microsoft.UProof/i		ALL
27	/%USERPROFILE%.Local Settings.History/i		ALL
28	/%APPDATA%.Microsoft.UProof/i 		ALL
29	/%LOCALAPPDATA%.Microsoft.Windows.Temporary Internet Files/i		ALL
\.


--
-- Data for Name: rest_client_histories; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.rest_client_histories (id, org_id, user_id, headers, body, url, http_method, "timestamp", use_full_path, show_result, skip_ssl, outcome, bookmark, bookmark_name) FROM stdin;
\.


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_delegate, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_site_admin, perm_regexp_access, perm_tagger, perm_template, perm_sharing_group, perm_tag_editor, perm_sighting, perm_object_template, default_role, memory_limit, max_execution_time, restricted_to_site_admin, perm_publish_zmq, perm_publish_kafka, perm_decaying, enforce_rate_limit, rate_limit_count) FROM stdin;
1	admin	2023-05-08 09:41:17+00	2023-05-08 09:41:17+00	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	f			f	t	t	t	f	0
2	Org Admin	2023-05-08 09:41:17+00	2023-05-08 09:41:17+00	t	t	t	t	t	f	t	t	f	t	f	f	t	t	t	t	t	f	f			f	t	t	t	f	0
3	User	2023-05-08 09:41:17+00	2023-05-08 09:41:17+00	t	t	t	f	f	f	f	t	f	t	f	f	t	f	f	f	t	f	t			f	f	f	t	f	0
4	Publisher	2023-05-08 09:41:17+00	2023-05-08 09:41:17+00	t	t	t	t	t	f	f	t	f	t	f	f	t	f	f	f	t	f	f			f	t	t	t	f	0
5	Sync user	2023-05-08 09:41:17+00	2023-05-08 09:41:17+00	t	t	t	t	t	t	f	t	f	t	f	f	t	f	t	t	t	f	f			f	t	t	t	f	0
6	Read Only	2023-05-08 09:41:17+00	2023-05-08 09:41:17+00	f	f	f	f	f	f	f	t	f	t	f	f	f	f	f	f	f	f	f			f	f	f	f	f	0
\.


--
-- Data for Name: servers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.servers (id, name, url, authkey, org_id, push, pull, push_sightings, lastpulledid, lastpushedid, organization, remote_org_id, publish_without_email, unpublish_event, self_signed, pull_rules, push_rules, cert_file, client_cert_file, internal, skip_proxy, caching_enabled, priority) FROM stdin;
\.


--
-- Data for Name: shadow_attribute_correlations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.shadow_attribute_correlations (id, org_id, value, distribution, a_distribution, sharing_group_id, a_sharing_group_id, attribute_id, "1_shadow_attribute_id", event_id, "1_event_id", info) FROM stdin;
\.


--
-- Data for Name: shadow_attributes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.shadow_attributes (id, old_id, event_id, type, category, value1, to_ids, uuid, value2, org_id, email, event_org_id, comment, event_uuid, deleted, "timestamp", proposal_to_delete, disable_correlation, first_seen, last_seen) FROM stdin;
\.


--
-- Data for Name: sharing_group_orgs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sharing_group_orgs (id, sharing_group_id, org_id, extend) FROM stdin;
\.


--
-- Data for Name: sharing_group_servers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sharing_group_servers (id, sharing_group_id, server_id, all_orgs) FROM stdin;
\.


--
-- Data for Name: sharing_groups; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sharing_groups (id, name, releasability, description, uuid, organisation_uuid, org_id, sync_user_id, active, created, modified, local, roaming) FROM stdin;
\.


--
-- Data for Name: sightingdb_orgs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sightingdb_orgs (id, sightingdb_id, org_id) FROM stdin;
\.


--
-- Data for Name: sightingdbs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sightingdbs (id, name, description, owner, host, port, "timestamp", enabled, skip_proxy, ssl_skip_verification, namespace) FROM stdin;
\.


--
-- Data for Name: sightings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sightings (id, attribute_id, event_id, org_id, date_sighting, uuid, source, type) FROM stdin;
\.


--
-- Data for Name: tag_collection_tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.tag_collection_tags (id, tag_collection_id, tag_id) FROM stdin;
\.


--
-- Data for Name: tag_collections; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.tag_collections (id, uuid, user_id, org_id, name, description, all_orgs) FROM stdin;
\.


--
-- Data for Name: tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.tags (id, name, colour, exportable, org_id, user_id, hide_tag, numerical_value) FROM stdin;
\.


--
-- Data for Name: tasks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.tasks (id, type, timer, scheduled_time, process_id, description, next_execution_time, message) FROM stdin;
\.


--
-- Data for Name: taxonomies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.taxonomies (id, namespace, description, version, enabled, exclusive, required) FROM stdin;
\.


--
-- Data for Name: taxonomy_entries; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.taxonomy_entries (id, taxonomy_predicate_id, value, expanded, colour, description, numerical_value) FROM stdin;
\.


--
-- Data for Name: taxonomy_predicates; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.taxonomy_predicates (id, taxonomy_id, value, expanded, colour, description, exclusive, numerical_value) FROM stdin;
\.


--
-- Data for Name: template_element_attributes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.template_element_attributes (id, template_element_id, name, description, to_ids, category, complex, type, mandatory, batch) FROM stdin;
1	1	From address	The source address from which the e-mail was sent.	t	Payload delivery	f	email-src	t	t
2	2	Malicious url	The malicious url in the e-mail body.	t	Payload delivery	f	url	t	t
3	4	E-mail subject	The subject line of the e-mail.	f	Payload delivery	f	email-subject	t	f
4	6	Spoofed source address	If an e-mail address was spoofed, specify which.	t	Payload delivery	f	email-src	f	f
5	7	Source IP	The source IP from which the e-mail was sent	t	Payload delivery	f	ip-src	f	t
6	8	X-mailer header	It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.	t	Payload delivery	f	text	f	t
7	12	From address	The source address from which the e-mail was sent	t	Payload delivery	f	email-src	t	t
8	15	Spoofed From Address	The spoofed source address from which the e-mail appears to be sent.	t	Payload delivery	f	email-src	f	t
9	17	E-mail Source IP	The IP address from which the e-mail was sent.	t	Payload delivery	f	ip-src	f	t
10	18	X-mailer header	It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.	t	Payload delivery	f	text	f	f
11	19	Malicious URL in the e-mail	If there was a malicious URL (or several), please specify it here	t	Payload delivery	f	ip-dst	f	t
12	20	Exploited vulnerablity	The vulnerabilities exploited during the payload delivery.	f	Payload delivery	f	vulnerability	f	t
13	22	C2 information	Command and Control information detected during the analysis.	t	Network activity	t	CnC	f	t
14	23	Artifacts dropped (File)	Any information about the files dropped during the analysis	t	Artifacts dropped	t	File	f	t
15	24	Artifacts dropped (Registry key)	Any registry keys touched during the analysis	t	Artifacts dropped	f	regkey	f	t
16	25	Artifacts dropped (Registry key + value)	Any registry keys created or altered together with the value.	t	Artifacts dropped	f	regkey|value	f	t
17	26	Persistance mechanism (filename)	Filenames (or filenames with filepaths) used as a persistence mechanism	t	Persistence mechanism	f	regkey|value	f	t
18	27	Persistence mechanism (Registry key)	Any registry keys touched as part of the persistence mechanism during the analysis 	t	Persistence mechanism	f	regkey	f	t
19	28	Persistence mechanism (Registry key + value)	Any registry keys created or modified together with their values used by the persistence mechanism	t	Persistence mechanism	f	regkey|value	f	t
20	34	C2 Information	You can drop any urls, domains, hostnames or IP addresses that were detected as the Command and Control during the analysis here. 	t	Network activity	t	CnC	f	t
21	35	Other Network Activity	Drop any applicable information about other network activity here. The attributes created here will NOT be marked for IDS exports.	f	Network activity	t	CnC	f	t
22	36	Vulnerability	The vulnerability or vulnerabilities that the sample exploits	f	Payload delivery	f	vulnerability	f	t
23	37	Artifacts Dropped (File)	Insert any data you have on dropped files here.	t	Artifacts dropped	t	File	f	t
24	38	Artifacts dropped (Registry key)	Any registry keys touched during the analysis	t	Artifacts dropped	f	regkey	f	t
25	39	Artifacts dropped (Registry key + value)	Any registry keys created or altered together with the value.	t	Artifacts dropped	f	regkey|value	f	t
26	42	Persistence mechanism (filename)	Insert any filenames used by the persistence mechanism.	t	Persistence mechanism	f	filename	f	t
27	43	Persistence Mechanism (Registry key)	Paste any registry keys that were created or modified as part of the persistence mechanism	t	Persistence mechanism	f	regkey	f	t
28	44	Persistence Mechanism (Registry key and value)	Paste any registry keys together with the values contained within created or modified by the persistence mechanism	t	Persistence mechanism	f	regkey|value	f	t
29	46	Network Indicators	Paste any combination of IP addresses, hostnames, domains or URL	t	Network activity	t	CnC	f	t
30	47	File Indicators	Paste any file hashes that you have (MD5, SHA1, SHA256) or filenames below. You can also add filename and hash pairs by using the following syntax for each applicable column: filename|hash 	t	Payload installation	t	File	f	t
\.


--
-- Data for Name: template_element_files; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.template_element_files (id, template_element_id, name, description, category, malware, mandatory, batch) FROM stdin;
1	14	Malicious Attachment	The file (or files) that was (were) attached to the e-mail itself.	Payload delivery	t	f	t
2	21	Payload installation	Payload installation detected during the analysis	Payload installation	t	f	t
3	30	Malware sample	The sample that the report is based on	Payload delivery	t	f	f
4	40	Artifacts dropped (Sample)	Upload any files that were dropped during the analysis.	Artifacts dropped	t	f	t
\.


--
-- Data for Name: template_element_texts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.template_element_texts (id, name, template_element_id, text) FROM stdin;
1	Required fields	3	The fields below are mandatory.
2	Optional information	5	All of the fields below are optional, please fill out anything that's applicable.
4	Required Fields	11	The following fields are mandatory
5	Optional information about the payload delivery	13	All of the fields below are optional, please fill out anything that's applicable. This section describes the payload delivery, including the e-mail itself, the attached file, the vulnerability it is exploiting and any malicious urls in the e-mail.
6	Optional information obtained from analysing the malicious file	16	Information about the analysis of the malware (if applicable). This can include C2 information, artifacts dropped during the analysis, persistance mechanism, etc.
7	Malware Sample	29	If you can, please upload the sample that the report revolves around.
8	Dropped Artifacts	31	Describe any dropped artifacts that you have encountered during your analysis
9	C2 Information	32	The following field deals with Command and Control information obtained during the analysis. All fields are optional.
10	Other Network Activity	33	If any other Network activity (such as an internet connection test) was detected during the analysis, please specify it using the following fields
11	Persistence mechanism	41	The following fields allow you to describe the persistence mechanism used by the malware
12	Indicators	45	Just paste your list of indicators based on type into the appropriate field. All of the fields are optional, so inputting a list of IP addresses into the Network indicator field for example is sufficient to complete this template.
\.


--
-- Data for Name: template_elements; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.template_elements (id, template_id, "position", element_definition) FROM stdin;
1	1	2	attribute
2	1	3	attribute
3	1	1	text
4	1	4	attribute
5	1	5	text
6	1	6	attribute
7	1	7	attribute
8	1	8	attribute
11	2	1	text
12	2	2	attribute
13	2	3	text
14	2	4	file
15	2	5	attribute
16	2	10	text
17	2	6	attribute
18	2	7	attribute
19	2	8	attribute
20	2	9	attribute
21	2	11	file
22	2	12	attribute
23	2	13	attribute
24	2	14	attribute
25	2	15	attribute
26	2	16	attribute
27	2	17	attribute
28	2	18	attribute
29	3	1	text
30	3	2	file
31	3	4	text
32	3	9	text
33	3	11	text
34	3	10	attribute
35	3	12	attribute
36	3	3	attribute
37	3	5	attribute
38	3	6	attribute
39	3	7	attribute
40	3	8	file
41	3	13	text
42	3	14	attribute
43	3	15	attribute
44	3	16	attribute
45	4	1	text
46	4	2	attribute
47	4	3	attribute
\.


--
-- Data for Name: template_tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.template_tags (id, template_id, tag_id) FROM stdin;
\.


--
-- Data for Name: templates; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.templates (id, name, description, org, share) FROM stdin;
1	Phishing E-mail	Create a MISP event about a Phishing E-mail.	MISP	t
2	Phishing E-mail with malicious attachment	A MISP event based on Spear-phishing containing a malicious attachment. This event can include anything from the description of the e-mail itself, the malicious attachment and its description as well as the results of the analysis done on the malicious f	MISP	t
3	Malware Report	This is a template for a generic malware report. 	MISP	t
4	Indicator List	A simple template for indicator lists.	MISP	t
\.


--
-- Data for Name: threads; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.threads (id, date_created, date_modified, distribution, user_id, post_count, event_id, title, org_id, sharing_group_id) FROM stdin;
\.


--
-- Data for Name: threat_levels; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.threat_levels (id, name, description, form_description) FROM stdin;
1	High	*high* means sophisticated APT malware or 0-day attack	Sophisticated APT malware or 0-day attack
2	Medium	*medium* means APT malware	APT malware
3	Low	*low* means mass-malware	Mass-malware
4	Undefined	*undefined* no risk	No risk
\.


--
-- Data for Name: user_settings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_settings (id, setting, value, user_id, "timestamp") FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.users (id, password, org_id, server_id, email, autoalert, authkey, invited_by, gpgkey, certif_public, nids_sid, termsaccepted, newsread, role_id, change_pw, contactalert, disabled, expiration, current_login, last_login, force_logout, date_created, date_modified) FROM stdin;
\.


--
-- Data for Name: warninglist_entries; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.warninglist_entries (id, value, warninglist_id) FROM stdin;
\.


--
-- Data for Name: warninglist_types; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.warninglist_types (id, type, warninglist_id) FROM stdin;
\.


--
-- Data for Name: warninglists; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.warninglists (id, name, type, description, version, enabled, warninglist_entry_count) FROM stdin;
\.


--
-- Name: admin_settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.admin_settings_id_seq', 3, true);


--
-- Name: allowedlist_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.allowedlist_id_seq', 1, true);


--
-- Name: attachment_scans_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attachment_scans_id_seq', 1, true);


--
-- Name: attribute_tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attribute_tags_id_seq', 1, true);


--
-- Name: attributes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attributes_id_seq', 1, true);


--
-- Name: auth_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.auth_keys_id_seq', 1, true);


--
-- Name: correlations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.correlations_id_seq', 1, true);


--
-- Name: dashboards_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.dashboards_id_seq', 1, true);


--
-- Name: decaying_model_mappings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.decaying_model_mappings_id_seq', 1, true);


--
-- Name: decaying_models_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.decaying_models_id_seq', 1, true);


--
-- Name: event_blocklists_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.event_blocklists_id_seq', 1, true);


--
-- Name: event_delegations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.event_delegations_id_seq', 1, true);


--
-- Name: event_graph_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.event_graph_id_seq', 1, true);


--
-- Name: event_locks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.event_locks_id_seq', 1, true);


--
-- Name: event_reports_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.event_reports_id_seq', 1, true);


--
-- Name: event_tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.event_tags_id_seq', 1, true);


--
-- Name: events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.events_id_seq', 1, true);


--
-- Name: favourite_tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.favourite_tags_id_seq', 1, true);


--
-- Name: feeds_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.feeds_id_seq', 2, true);


--
-- Name: fuzzy_correlate_ssdeep_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.fuzzy_correlate_ssdeep_id_seq', 1, true);


--
-- Name: galaxies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.galaxies_id_seq', 1, true);


--
-- Name: galaxy_clusters_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.galaxy_clusters_id_seq', 1, true);


--
-- Name: galaxy_elements_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.galaxy_elements_id_seq', 1, true);


--
-- Name: galaxy_reference_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.galaxy_reference_id_seq', 1, true);


--
-- Name: inbox_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.inbox_id_seq', 1, true);


--
-- Name: jobs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.jobs_id_seq', 1, true);


--
-- Name: logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.logs_id_seq', 1, true);


--
-- Name: news_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.news_id_seq', 1, true);


--
-- Name: noticelist_entries_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.noticelist_entries_id_seq', 1, true);


--
-- Name: noticelists_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.noticelists_id_seq', 1, true);


--
-- Name: notification_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.notification_logs_id_seq', 1, true);


--
-- Name: object_references_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.object_references_id_seq', 1, true);


--
-- Name: object_relationships_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.object_relationships_id_seq', 1, true);


--
-- Name: object_template_elements_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.object_template_elements_id_seq', 1, true);


--
-- Name: object_templates_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.object_templates_id_seq', 1, true);


--
-- Name: objects_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.objects_id_seq', 1, true);


--
-- Name: org_blocklists_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.org_blocklists_id_seq', 2, true);


--
-- Name: organisations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.organisations_id_seq', 1, true);


--
-- Name: posts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.posts_id_seq', 1, true);


--
-- Name: regexp_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.regexp_id_seq', 29, true);


--
-- Name: rest_client_histories_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.rest_client_histories_id_seq', 1, true);


--
-- Name: roles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.roles_id_seq', 6, true);


--
-- Name: servers_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.servers_id_seq', 1, true);


--
-- Name: shadow_attribute_correlations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.shadow_attribute_correlations_id_seq', 1, true);


--
-- Name: shadow_attributes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.shadow_attributes_id_seq', 1, true);


--
-- Name: sharing_group_orgs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sharing_group_orgs_id_seq', 1, true);


--
-- Name: sharing_group_servers_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sharing_group_servers_id_seq', 1, true);


--
-- Name: sharing_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sharing_groups_id_seq', 1, true);


--
-- Name: sightingdb_orgs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sightingdb_orgs_id_seq', 1, true);


--
-- Name: sightingdbs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sightingdbs_id_seq', 1, true);


--
-- Name: sightings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sightings_id_seq', 1, true);


--
-- Name: tag_collection_tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.tag_collection_tags_id_seq', 1, true);


--
-- Name: tag_collections_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.tag_collections_id_seq', 1, true);


--
-- Name: tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.tags_id_seq', 1, true);


--
-- Name: tasks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.tasks_id_seq', 1, true);


--
-- Name: taxonomies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.taxonomies_id_seq', 1, true);


--
-- Name: taxonomy_entries_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.taxonomy_entries_id_seq', 1, true);


--
-- Name: taxonomy_predicates_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.taxonomy_predicates_id_seq', 1, true);


--
-- Name: template_element_attributes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.template_element_attributes_id_seq', 30, true);


--
-- Name: template_element_files_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.template_element_files_id_seq', 4, true);


--
-- Name: template_element_texts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.template_element_texts_id_seq', 12, true);


--
-- Name: template_elements_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.template_elements_id_seq', 47, true);


--
-- Name: template_tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.template_tags_id_seq', 1, true);


--
-- Name: templates_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.templates_id_seq', 4, true);


--
-- Name: threads_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.threads_id_seq', 1, true);


--
-- Name: threat_levels_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.threat_levels_id_seq', 4, true);


--
-- Name: user_settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.user_settings_id_seq', 1, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.users_id_seq', 1, true);


--
-- Name: warninglist_entries_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.warninglist_entries_id_seq', 1, true);


--
-- Name: warninglist_types_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.warninglist_types_id_seq', 1, true);


--
-- Name: warninglists_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.warninglists_id_seq', 1, true);


--
-- Name: admin_settings idx_16390_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_settings
    ADD CONSTRAINT idx_16390_primary PRIMARY KEY (id);


--
-- Name: allowedlist idx_16397_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.allowedlist
    ADD CONSTRAINT idx_16397_primary PRIMARY KEY (id);


--
-- Name: attachment_scans idx_16404_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachment_scans
    ADD CONSTRAINT idx_16404_primary PRIMARY KEY (id);


--
-- Name: attributes idx_16410_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attributes
    ADD CONSTRAINT idx_16410_primary PRIMARY KEY (id);


--
-- Name: attribute_tags idx_16424_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_tags
    ADD CONSTRAINT idx_16424_primary PRIMARY KEY (id);


--
-- Name: auth_keys idx_16430_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_keys
    ADD CONSTRAINT idx_16430_primary PRIMARY KEY (id);


--
-- Name: cake_sessions idx_16441_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cake_sessions
    ADD CONSTRAINT idx_16441_primary PRIMARY KEY (id);


--
-- Name: correlations idx_16448_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlations
    ADD CONSTRAINT idx_16448_primary PRIMARY KEY (id);


--
-- Name: dashboards idx_16455_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dashboards
    ADD CONSTRAINT idx_16455_primary PRIMARY KEY (id);


--
-- Name: decaying_models idx_16468_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.decaying_models
    ADD CONSTRAINT idx_16468_primary PRIMARY KEY (id);


--
-- Name: decaying_model_mappings idx_16480_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.decaying_model_mappings
    ADD CONSTRAINT idx_16480_primary PRIMARY KEY (id);


--
-- Name: events idx_16485_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT idx_16485_primary PRIMARY KEY (id);


--
-- Name: event_blocklists idx_16502_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_blocklists
    ADD CONSTRAINT idx_16502_primary PRIMARY KEY (id);


--
-- Name: event_delegations idx_16509_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_delegations
    ADD CONSTRAINT idx_16509_primary PRIMARY KEY (id);


--
-- Name: event_graph idx_16517_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_graph
    ADD CONSTRAINT idx_16517_primary PRIMARY KEY (id);


--
-- Name: event_locks idx_16526_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_locks
    ADD CONSTRAINT idx_16526_primary PRIMARY KEY (id);


--
-- Name: event_reports idx_16532_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_reports
    ADD CONSTRAINT idx_16532_primary PRIMARY KEY (id);


--
-- Name: event_tags idx_16541_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_tags
    ADD CONSTRAINT idx_16541_primary PRIMARY KEY (id);


--
-- Name: favourite_tags idx_16547_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.favourite_tags
    ADD CONSTRAINT idx_16547_primary PRIMARY KEY (id);


--
-- Name: feeds idx_16552_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feeds
    ADD CONSTRAINT idx_16552_primary PRIMARY KEY (id);


--
-- Name: fuzzy_correlate_ssdeep idx_16576_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fuzzy_correlate_ssdeep
    ADD CONSTRAINT idx_16576_primary PRIMARY KEY (id);


--
-- Name: galaxies idx_16581_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxies
    ADD CONSTRAINT idx_16581_primary PRIMARY KEY (id);


--
-- Name: galaxy_clusters idx_16591_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxy_clusters
    ADD CONSTRAINT idx_16591_primary PRIMARY KEY (id);


--
-- Name: galaxy_elements idx_16602_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxy_elements
    ADD CONSTRAINT idx_16602_primary PRIMARY KEY (id);


--
-- Name: galaxy_reference idx_16610_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxy_reference
    ADD CONSTRAINT idx_16610_primary PRIMARY KEY (id);


--
-- Name: inbox idx_16617_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbox
    ADD CONSTRAINT idx_16617_primary PRIMARY KEY (id);


--
-- Name: jobs idx_16626_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT idx_16626_primary PRIMARY KEY (id);


--
-- Name: logs idx_16638_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.logs
    ADD CONSTRAINT idx_16638_primary PRIMARY KEY (id);


--
-- Name: news idx_16648_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.news
    ADD CONSTRAINT idx_16648_primary PRIMARY KEY (id);


--
-- Name: noticelists idx_16655_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.noticelists
    ADD CONSTRAINT idx_16655_primary PRIMARY KEY (id);


--
-- Name: noticelist_entries idx_16665_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.noticelist_entries
    ADD CONSTRAINT idx_16665_primary PRIMARY KEY (id);


--
-- Name: notification_logs idx_16672_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_logs
    ADD CONSTRAINT idx_16672_primary PRIMARY KEY (id);


--
-- Name: objects idx_16678_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.objects
    ADD CONSTRAINT idx_16678_primary PRIMARY KEY (id);


--
-- Name: object_references idx_16692_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_references
    ADD CONSTRAINT idx_16692_primary PRIMARY KEY (id);


--
-- Name: object_relationships idx_16706_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_relationships
    ADD CONSTRAINT idx_16706_primary PRIMARY KEY (id);


--
-- Name: object_templates idx_16714_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_templates
    ADD CONSTRAINT idx_16714_primary PRIMARY KEY (id);


--
-- Name: object_template_elements idx_16726_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_template_elements
    ADD CONSTRAINT idx_16726_primary PRIMARY KEY (id);


--
-- Name: organisations idx_16736_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organisations
    ADD CONSTRAINT idx_16736_primary PRIMARY KEY (id);


--
-- Name: org_blocklists idx_16749_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_blocklists
    ADD CONSTRAINT idx_16749_primary PRIMARY KEY (id);


--
-- Name: posts idx_16756_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posts
    ADD CONSTRAINT idx_16756_primary PRIMARY KEY (id);


--
-- Name: regexp idx_16765_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.regexp
    ADD CONSTRAINT idx_16765_primary PRIMARY KEY (id);


--
-- Name: rest_client_histories idx_16773_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rest_client_histories
    ADD CONSTRAINT idx_16773_primary PRIMARY KEY (id);


--
-- Name: roles idx_16787_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT idx_16787_primary PRIMARY KEY (id);


--
-- Name: servers idx_16813_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.servers
    ADD CONSTRAINT idx_16813_primary PRIMARY KEY (id);


--
-- Name: shadow_attributes idx_16830_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shadow_attributes
    ADD CONSTRAINT idx_16830_primary PRIMARY KEY (id);


--
-- Name: shadow_attribute_correlations idx_16844_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shadow_attribute_correlations
    ADD CONSTRAINT idx_16844_primary PRIMARY KEY (id);


--
-- Name: sharing_groups idx_16851_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sharing_groups
    ADD CONSTRAINT idx_16851_primary PRIMARY KEY (id);


--
-- Name: sharing_group_orgs idx_16860_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sharing_group_orgs
    ADD CONSTRAINT idx_16860_primary PRIMARY KEY (id);


--
-- Name: sharing_group_servers idx_16866_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sharing_group_servers
    ADD CONSTRAINT idx_16866_primary PRIMARY KEY (id);


--
-- Name: sightingdbs idx_16871_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sightingdbs
    ADD CONSTRAINT idx_16871_primary PRIMARY KEY (id);


--
-- Name: sightingdb_orgs idx_16886_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sightingdb_orgs
    ADD CONSTRAINT idx_16886_primary PRIMARY KEY (id);


--
-- Name: sightings idx_16891_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sightings
    ADD CONSTRAINT idx_16891_primary PRIMARY KEY (id);


--
-- Name: tags idx_16901_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT idx_16901_primary PRIMARY KEY (id);


--
-- Name: tag_collections idx_16909_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tag_collections
    ADD CONSTRAINT idx_16909_primary PRIMARY KEY (id);


--
-- Name: tag_collection_tags idx_16918_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tag_collection_tags
    ADD CONSTRAINT idx_16918_primary PRIMARY KEY (id);


--
-- Name: tasks idx_16923_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT idx_16923_primary PRIMARY KEY (id);


--
-- Name: taxonomies idx_16932_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.taxonomies
    ADD CONSTRAINT idx_16932_primary PRIMARY KEY (id);


--
-- Name: taxonomy_entries idx_16942_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.taxonomy_entries
    ADD CONSTRAINT idx_16942_primary PRIMARY KEY (id);


--
-- Name: taxonomy_predicates idx_16950_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.taxonomy_predicates
    ADD CONSTRAINT idx_16950_primary PRIMARY KEY (id);


--
-- Name: templates idx_16959_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.templates
    ADD CONSTRAINT idx_16959_primary PRIMARY KEY (id);


--
-- Name: template_elements idx_16966_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_elements
    ADD CONSTRAINT idx_16966_primary PRIMARY KEY (id);


--
-- Name: template_element_attributes idx_16971_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_element_attributes
    ADD CONSTRAINT idx_16971_primary PRIMARY KEY (id);


--
-- Name: template_element_files idx_16979_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_element_files
    ADD CONSTRAINT idx_16979_primary PRIMARY KEY (id);


--
-- Name: template_element_texts idx_16986_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_element_texts
    ADD CONSTRAINT idx_16986_primary PRIMARY KEY (id);


--
-- Name: template_tags idx_16993_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_tags
    ADD CONSTRAINT idx_16993_primary PRIMARY KEY (id);


--
-- Name: threads idx_16998_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threads
    ADD CONSTRAINT idx_16998_primary PRIMARY KEY (id);


--
-- Name: threat_levels idx_17003_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_levels
    ADD CONSTRAINT idx_17003_primary PRIMARY KEY (id);


--
-- Name: users idx_17011_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT idx_17011_primary PRIMARY KEY (id);


--
-- Name: user_settings idx_17032_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT idx_17032_primary PRIMARY KEY (id);


--
-- Name: warninglists idx_17039_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.warninglists
    ADD CONSTRAINT idx_17039_primary PRIMARY KEY (id);


--
-- Name: warninglist_entries idx_17050_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.warninglist_entries
    ADD CONSTRAINT idx_17050_primary PRIMARY KEY (id);


--
-- Name: warninglist_types idx_17057_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.warninglist_types
    ADD CONSTRAINT idx_17057_primary PRIMARY KEY (id);


--
-- Name: idx_16390_setting; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16390_setting ON public.admin_settings USING btree (setting);


--
-- Name: idx_16404_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16404_index ON public.attachment_scans USING btree (type, attribute_id);


--
-- Name: idx_16410_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_category ON public.attributes USING btree (category);


--
-- Name: idx_16410_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_event_id ON public.attributes USING btree (event_id);


--
-- Name: idx_16410_first_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_first_seen ON public.attributes USING btree (first_seen);


--
-- Name: idx_16410_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_last_seen ON public.attributes USING btree (last_seen);


--
-- Name: idx_16410_object_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_object_id ON public.attributes USING btree (object_id);


--
-- Name: idx_16410_object_relation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_object_relation ON public.attributes USING btree (object_relation);


--
-- Name: idx_16410_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_sharing_group_id ON public.attributes USING btree (sharing_group_id);


--
-- Name: idx_16410_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_type ON public.attributes USING btree (type);


--
-- Name: idx_16410_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16410_uuid ON public.attributes USING btree (uuid);


--
-- Name: idx_16410_value1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_value1 ON public.attributes USING btree (value1);


--
-- Name: idx_16410_value2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16410_value2 ON public.attributes USING btree (value2);


--
-- Name: idx_16424_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16424_attribute_id ON public.attribute_tags USING btree (attribute_id);


--
-- Name: idx_16424_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16424_event_id ON public.attribute_tags USING btree (event_id);


--
-- Name: idx_16424_tag_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16424_tag_id ON public.attribute_tags USING btree (tag_id);


--
-- Name: idx_16430_authkey_end; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16430_authkey_end ON public.auth_keys USING btree (authkey_end);


--
-- Name: idx_16430_authkey_start; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16430_authkey_start ON public.auth_keys USING btree (authkey_start);


--
-- Name: idx_16430_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16430_created ON public.auth_keys USING btree (created);


--
-- Name: idx_16430_expiration; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16430_expiration ON public.auth_keys USING btree (expiration);


--
-- Name: idx_16430_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16430_user_id ON public.auth_keys USING btree (user_id);


--
-- Name: idx_16441_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16441_expires ON public.cake_sessions USING btree (expires);


--
-- Name: idx_16448_1_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16448_1_attribute_id ON public.correlations USING btree ("1_attribute_id");


--
-- Name: idx_16448_1_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16448_1_event_id ON public.correlations USING btree ("1_event_id");


--
-- Name: idx_16448_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16448_attribute_id ON public.correlations USING btree (attribute_id);


--
-- Name: idx_16448_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16448_event_id ON public.correlations USING btree (event_id);


--
-- Name: idx_16455_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16455_name ON public.dashboards USING btree (name);


--
-- Name: idx_16455_restrict_to_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16455_restrict_to_org_id ON public.dashboards USING btree (restrict_to_org_id);


--
-- Name: idx_16455_restrict_to_permission_flag; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16455_restrict_to_permission_flag ON public.dashboards USING btree (restrict_to_permission_flag);


--
-- Name: idx_16455_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16455_user_id ON public.dashboards USING btree (user_id);


--
-- Name: idx_16455_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16455_uuid ON public.dashboards USING btree (uuid);


--
-- Name: idx_16468_all_orgs; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16468_all_orgs ON public.decaying_models USING btree (all_orgs);


--
-- Name: idx_16468_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16468_enabled ON public.decaying_models USING btree (enabled);


--
-- Name: idx_16468_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16468_name ON public.decaying_models USING btree (name);


--
-- Name: idx_16468_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16468_org_id ON public.decaying_models USING btree (org_id);


--
-- Name: idx_16468_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16468_uuid ON public.decaying_models USING btree (uuid);


--
-- Name: idx_16468_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16468_version ON public.decaying_models USING btree (version);


--
-- Name: idx_16480_model_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16480_model_id ON public.decaying_model_mappings USING btree (model_id);


--
-- Name: idx_16485_extends_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16485_extends_uuid ON public.events USING btree (extends_uuid);


--
-- Name: idx_16485_info; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16485_info ON public.events USING btree (info);


--
-- Name: idx_16485_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16485_org_id ON public.events USING btree (org_id);


--
-- Name: idx_16485_orgc_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16485_orgc_id ON public.events USING btree (orgc_id);


--
-- Name: idx_16485_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16485_sharing_group_id ON public.events USING btree (sharing_group_id);


--
-- Name: idx_16485_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16485_uuid ON public.events USING btree (uuid);


--
-- Name: idx_16502_event_orgc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16502_event_orgc ON public.event_blocklists USING btree (event_orgc);


--
-- Name: idx_16502_event_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16502_event_uuid ON public.event_blocklists USING btree (event_uuid);


--
-- Name: idx_16509_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16509_event_id ON public.event_delegations USING btree (event_id);


--
-- Name: idx_16509_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16509_org_id ON public.event_delegations USING btree (org_id);


--
-- Name: idx_16517_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16517_event_id ON public.event_graph USING btree (event_id);


--
-- Name: idx_16517_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16517_org_id ON public.event_graph USING btree (org_id);


--
-- Name: idx_16517_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16517_timestamp ON public.event_graph USING btree ("timestamp");


--
-- Name: idx_16517_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16517_user_id ON public.event_graph USING btree (user_id);


--
-- Name: idx_16526_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16526_event_id ON public.event_locks USING btree (event_id);


--
-- Name: idx_16526_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16526_timestamp ON public.event_locks USING btree ("timestamp");


--
-- Name: idx_16526_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16526_user_id ON public.event_locks USING btree (user_id);


--
-- Name: idx_16532_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16532_event_id ON public.event_reports USING btree (event_id);


--
-- Name: idx_16532_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16532_name ON public.event_reports USING btree (name);


--
-- Name: idx_16532_u_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16532_u_uuid ON public.event_reports USING btree (uuid);


--
-- Name: idx_16541_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16541_event_id ON public.event_tags USING btree (event_id);


--
-- Name: idx_16541_tag_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16541_tag_id ON public.event_tags USING btree (tag_id);


--
-- Name: idx_16547_tag_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16547_tag_id ON public.favourite_tags USING btree (tag_id);


--
-- Name: idx_16547_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16547_user_id ON public.favourite_tags USING btree (user_id);


--
-- Name: idx_16552_input_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16552_input_source ON public.feeds USING btree (input_source);


--
-- Name: idx_16552_orgc_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16552_orgc_id ON public.feeds USING btree (orgc_id);


--
-- Name: idx_16576_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16576_attribute_id ON public.fuzzy_correlate_ssdeep USING btree (attribute_id);


--
-- Name: idx_16576_chunk; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16576_chunk ON public.fuzzy_correlate_ssdeep USING btree (chunk);


--
-- Name: idx_16581_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16581_name ON public.galaxies USING btree (name);


--
-- Name: idx_16581_namespace; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16581_namespace ON public.galaxies USING btree (namespace);


--
-- Name: idx_16581_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16581_type ON public.galaxies USING btree (type);


--
-- Name: idx_16581_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16581_uuid ON public.galaxies USING btree (uuid);


--
-- Name: idx_16591_collection_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16591_collection_uuid ON public.galaxy_clusters USING btree (collection_uuid);


--
-- Name: idx_16591_galaxy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16591_galaxy_id ON public.galaxy_clusters USING btree (galaxy_id);


--
-- Name: idx_16591_tag_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16591_tag_name ON public.galaxy_clusters USING btree (tag_name);


--
-- Name: idx_16591_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16591_type ON public.galaxy_clusters USING btree (type);


--
-- Name: idx_16591_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16591_uuid ON public.galaxy_clusters USING btree (uuid);


--
-- Name: idx_16591_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16591_value ON public.galaxy_clusters USING btree (value);


--
-- Name: idx_16591_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16591_version ON public.galaxy_clusters USING btree (version);


--
-- Name: idx_16602_galaxy_cluster_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16602_galaxy_cluster_id ON public.galaxy_elements USING btree (galaxy_cluster_id);


--
-- Name: idx_16602_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16602_key ON public.galaxy_elements USING btree (key);


--
-- Name: idx_16602_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16602_value ON public.galaxy_elements USING btree (value);


--
-- Name: idx_16610_galaxy_cluster_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16610_galaxy_cluster_id ON public.galaxy_reference USING btree (galaxy_cluster_id);


--
-- Name: idx_16610_referenced_galaxy_cluster_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16610_referenced_galaxy_cluster_id ON public.galaxy_reference USING btree (referenced_galaxy_cluster_id);


--
-- Name: idx_16610_referenced_galaxy_cluster_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16610_referenced_galaxy_cluster_type ON public.galaxy_reference USING btree (referenced_galaxy_cluster_type);


--
-- Name: idx_16610_referenced_galaxy_cluster_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16610_referenced_galaxy_cluster_value ON public.galaxy_reference USING btree (referenced_galaxy_cluster_value);


--
-- Name: idx_16617_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16617_ip ON public.inbox USING btree (ip);


--
-- Name: idx_16617_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16617_timestamp ON public.inbox USING btree ("timestamp");


--
-- Name: idx_16617_title; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16617_title ON public.inbox USING btree (title);


--
-- Name: idx_16617_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16617_type ON public.inbox USING btree (type);


--
-- Name: idx_16617_user_agent_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16617_user_agent_sha256 ON public.inbox USING btree (user_agent_sha256);


--
-- Name: idx_16617_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16617_uuid ON public.inbox USING btree (uuid);


--
-- Name: idx_16655_geographical_area; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16655_geographical_area ON public.noticelists USING btree (geographical_area);


--
-- Name: idx_16655_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16655_name ON public.noticelists USING btree (name);


--
-- Name: idx_16665_noticelist_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16665_noticelist_id ON public.noticelist_entries USING btree (noticelist_id);


--
-- Name: idx_16672_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16672_org_id ON public.notification_logs USING btree (org_id);


--
-- Name: idx_16672_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16672_type ON public.notification_logs USING btree (type);


--
-- Name: idx_16678_distribution; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16678_distribution ON public.objects USING btree (distribution);


--
-- Name: idx_16678_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16678_event_id ON public.objects USING btree (event_id);


--
-- Name: idx_16678_first_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16678_first_seen ON public.objects USING btree (first_seen);


--
-- Name: idx_16678_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16678_last_seen ON public.objects USING btree (last_seen);


--
-- Name: idx_16678_meta-category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_16678_meta-category" ON public.objects USING btree ("meta-category");


--
-- Name: idx_16678_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16678_name ON public.objects USING btree (name);


--
-- Name: idx_16678_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16678_sharing_group_id ON public.objects USING btree (sharing_group_id);


--
-- Name: idx_16678_template_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16678_template_uuid ON public.objects USING btree (template_uuid);


--
-- Name: idx_16678_template_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16678_template_version ON public.objects USING btree (template_version);


--
-- Name: idx_16678_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16678_timestamp ON public.objects USING btree ("timestamp");


--
-- Name: idx_16678_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16678_uuid ON public.objects USING btree (uuid);


--
-- Name: idx_16692_object_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16692_object_id ON public.object_references USING btree (object_id);


--
-- Name: idx_16692_referenced_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16692_referenced_id ON public.object_references USING btree (referenced_id);


--
-- Name: idx_16692_referenced_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16692_referenced_uuid ON public.object_references USING btree (referenced_uuid);


--
-- Name: idx_16692_relationship_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16692_relationship_type ON public.object_references USING btree (relationship_type);


--
-- Name: idx_16692_source_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16692_source_uuid ON public.object_references USING btree (source_uuid);


--
-- Name: idx_16692_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16692_timestamp ON public.object_references USING btree ("timestamp");


--
-- Name: idx_16692_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16692_uuid ON public.object_references USING btree (uuid);


--
-- Name: idx_16706_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16706_name ON public.object_relationships USING btree (name);


--
-- Name: idx_16714_meta-category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_16714_meta-category" ON public.object_templates USING btree ("meta-category");


--
-- Name: idx_16714_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16714_name ON public.object_templates USING btree (name);


--
-- Name: idx_16714_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16714_org_id ON public.object_templates USING btree (org_id);


--
-- Name: idx_16714_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16714_user_id ON public.object_templates USING btree (user_id);


--
-- Name: idx_16714_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16714_uuid ON public.object_templates USING btree (uuid);


--
-- Name: idx_16726_object_relation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16726_object_relation ON public.object_template_elements USING btree (object_relation);


--
-- Name: idx_16726_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16726_type ON public.object_template_elements USING btree (type);


--
-- Name: idx_16736_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16736_name ON public.organisations USING btree (name);


--
-- Name: idx_16736_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16736_uuid ON public.organisations USING btree (uuid);


--
-- Name: idx_16749_org_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16749_org_name ON public.org_blocklists USING btree (org_name);


--
-- Name: idx_16749_org_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16749_org_uuid ON public.org_blocklists USING btree (org_uuid);


--
-- Name: idx_16756_post_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16756_post_id ON public.posts USING btree (post_id);


--
-- Name: idx_16756_thread_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16756_thread_id ON public.posts USING btree (thread_id);


--
-- Name: idx_16773_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16773_org_id ON public.rest_client_histories USING btree (org_id);


--
-- Name: idx_16773_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16773_timestamp ON public.rest_client_histories USING btree ("timestamp");


--
-- Name: idx_16773_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16773_user_id ON public.rest_client_histories USING btree (user_id);


--
-- Name: idx_16813_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16813_org_id ON public.servers USING btree (org_id);


--
-- Name: idx_16813_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16813_priority ON public.servers USING btree (priority);


--
-- Name: idx_16813_remote_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16813_remote_org_id ON public.servers USING btree (remote_org_id);


--
-- Name: idx_16830_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_category ON public.shadow_attributes USING btree (category);


--
-- Name: idx_16830_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_event_id ON public.shadow_attributes USING btree (event_id);


--
-- Name: idx_16830_event_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_event_org_id ON public.shadow_attributes USING btree (event_org_id);


--
-- Name: idx_16830_event_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_event_uuid ON public.shadow_attributes USING btree (event_uuid);


--
-- Name: idx_16830_first_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_first_seen ON public.shadow_attributes USING btree (first_seen);


--
-- Name: idx_16830_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_last_seen ON public.shadow_attributes USING btree (last_seen);


--
-- Name: idx_16830_old_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_old_id ON public.shadow_attributes USING btree (old_id);


--
-- Name: idx_16830_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_type ON public.shadow_attributes USING btree (type);


--
-- Name: idx_16830_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_uuid ON public.shadow_attributes USING btree (uuid);


--
-- Name: idx_16830_value1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_value1 ON public.shadow_attributes USING btree (value1);


--
-- Name: idx_16830_value2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16830_value2 ON public.shadow_attributes USING btree (value2);


--
-- Name: idx_16844_1_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16844_1_event_id ON public.shadow_attribute_correlations USING btree ("1_event_id");


--
-- Name: idx_16844_1_shadow_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16844_1_shadow_attribute_id ON public.shadow_attribute_correlations USING btree ("1_shadow_attribute_id");


--
-- Name: idx_16844_a_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16844_a_sharing_group_id ON public.shadow_attribute_correlations USING btree (a_sharing_group_id);


--
-- Name: idx_16844_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16844_attribute_id ON public.shadow_attribute_correlations USING btree (attribute_id);


--
-- Name: idx_16844_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16844_event_id ON public.shadow_attribute_correlations USING btree (event_id);


--
-- Name: idx_16844_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16844_org_id ON public.shadow_attribute_correlations USING btree (org_id);


--
-- Name: idx_16844_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16844_sharing_group_id ON public.shadow_attribute_correlations USING btree (sharing_group_id);


--
-- Name: idx_16851_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16851_name ON public.sharing_groups USING btree (name);


--
-- Name: idx_16851_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16851_org_id ON public.sharing_groups USING btree (org_id);


--
-- Name: idx_16851_organisation_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16851_organisation_uuid ON public.sharing_groups USING btree (organisation_uuid);


--
-- Name: idx_16851_sync_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16851_sync_user_id ON public.sharing_groups USING btree (sync_user_id);


--
-- Name: idx_16851_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16851_uuid ON public.sharing_groups USING btree (uuid);


--
-- Name: idx_16860_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16860_org_id ON public.sharing_group_orgs USING btree (org_id);


--
-- Name: idx_16860_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16860_sharing_group_id ON public.sharing_group_orgs USING btree (sharing_group_id);


--
-- Name: idx_16866_server_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16866_server_id ON public.sharing_group_servers USING btree (server_id);


--
-- Name: idx_16866_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16866_sharing_group_id ON public.sharing_group_servers USING btree (sharing_group_id);


--
-- Name: idx_16871_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16871_host ON public.sightingdbs USING btree (host);


--
-- Name: idx_16871_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16871_name ON public.sightingdbs USING btree (name);


--
-- Name: idx_16871_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16871_owner ON public.sightingdbs USING btree (owner);


--
-- Name: idx_16871_port; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16871_port ON public.sightingdbs USING btree (port);


--
-- Name: idx_16886_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16886_org_id ON public.sightingdb_orgs USING btree (org_id);


--
-- Name: idx_16886_sightingdb_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16886_sightingdb_id ON public.sightingdb_orgs USING btree (sightingdb_id);


--
-- Name: idx_16891_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16891_attribute_id ON public.sightings USING btree (attribute_id);


--
-- Name: idx_16891_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16891_event_id ON public.sightings USING btree (event_id);


--
-- Name: idx_16891_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16891_org_id ON public.sightings USING btree (org_id);


--
-- Name: idx_16891_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16891_source ON public.sightings USING btree (source);


--
-- Name: idx_16891_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16891_type ON public.sightings USING btree (type);


--
-- Name: idx_16891_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16891_uuid ON public.sightings USING btree (uuid);


--
-- Name: idx_16901_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_16901_name ON public.tags USING btree (name);


--
-- Name: idx_16901_numerical_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16901_numerical_value ON public.tags USING btree (numerical_value);


--
-- Name: idx_16901_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16901_org_id ON public.tags USING btree (org_id);


--
-- Name: idx_16901_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16901_user_id ON public.tags USING btree (user_id);


--
-- Name: idx_16909_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16909_org_id ON public.tag_collections USING btree (org_id);


--
-- Name: idx_16909_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16909_user_id ON public.tag_collections USING btree (user_id);


--
-- Name: idx_16909_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16909_uuid ON public.tag_collections USING btree (uuid);


--
-- Name: idx_16918_tag_collection_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16918_tag_collection_id ON public.tag_collection_tags USING btree (tag_collection_id);


--
-- Name: idx_16918_tag_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16918_tag_id ON public.tag_collection_tags USING btree (tag_id);


--
-- Name: idx_16942_numerical_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16942_numerical_value ON public.taxonomy_entries USING btree (numerical_value);


--
-- Name: idx_16942_taxonomy_predicate_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16942_taxonomy_predicate_id ON public.taxonomy_entries USING btree (taxonomy_predicate_id);


--
-- Name: idx_16950_numerical_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16950_numerical_value ON public.taxonomy_predicates USING btree (numerical_value);


--
-- Name: idx_16950_taxonomy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16950_taxonomy_id ON public.taxonomy_predicates USING btree (taxonomy_id);


--
-- Name: idx_16998_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16998_event_id ON public.threads USING btree (event_id);


--
-- Name: idx_16998_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16998_org_id ON public.threads USING btree (org_id);


--
-- Name: idx_16998_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16998_sharing_group_id ON public.threads USING btree (sharing_group_id);


--
-- Name: idx_16998_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_16998_user_id ON public.threads USING btree (user_id);


--
-- Name: idx_17011_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_17011_email ON public.users USING btree (email);


--
-- Name: idx_17011_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_17011_org_id ON public.users USING btree (org_id);


--
-- Name: idx_17011_server_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_17011_server_id ON public.users USING btree (server_id);


--
-- Name: idx_17032_setting; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_17032_setting ON public.user_settings USING btree (setting);


--
-- Name: idx_17032_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_17032_timestamp ON public.user_settings USING btree ("timestamp");


--
-- Name: idx_17032_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_17032_user_id ON public.user_settings USING btree (user_id);


--
-- Name: idx_17050_warninglist_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_17050_warninglist_id ON public.warninglist_entries USING btree (warninglist_id);


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: -
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;


--
-- PostgreSQL database dump complete
--

