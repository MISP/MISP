--
-- PostgreSQL database dump
--

-- Dumped from database version 11.1
-- Dumped by pg_dump version 11.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_with_oids = false;

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
-- Name: attribute_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attribute_tags (
    id bigint NOT NULL,
    attribute_id bigint NOT NULL,
    event_id bigint NOT NULL,
    tag_id bigint NOT NULL
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
    object_relation character varying(255),
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
    disable_correlation boolean DEFAULT false NOT NULL
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
    a_sharing_group_id bigint NOT NULL,
    date date NOT NULL,
    info text NOT NULL
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
-- Name: event_blacklists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_blacklists (
    id bigint NOT NULL,
    event_uuid character varying(40) NOT NULL,
    created timestamp with time zone NOT NULL,
    event_info text NOT NULL,
    comment text,
    event_orgc character varying(255) NOT NULL
);


--
-- Name: event_blacklists_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_blacklists_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_blacklists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_blacklists_id_seq OWNED BY public.event_blacklists.id;


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
-- Name: event_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_tags (
    id bigint NOT NULL,
    event_id bigint NOT NULL,
    tag_id bigint NOT NULL
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
    caching_enabled boolean DEFAULT false NOT NULL
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
    namespace character varying(255) DEFAULT 'misp'::character varying NOT NULL
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
    uuid character varying(255) NOT NULL,
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
    process_id character varying(32),
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
    geographical_area character varying(255),
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
-- Name: object_references; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.object_references (
    id bigint NOT NULL,
    uuid character varying(40),
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    object_id bigint NOT NULL,
    event_id bigint NOT NULL,
    source_uuid character varying(40),
    referenced_uuid character varying(40),
    referenced_id bigint NOT NULL,
    referenced_type bigint DEFAULT '0'::bigint NOT NULL,
    relationship_type character varying(255),
    comment text NOT NULL,
    deleted smallint DEFAULT '0'::smallint NOT NULL
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
    name character varying(255),
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
    object_relation character varying(255),
    type character varying(255),
    "ui-priority" bigint NOT NULL,
    categories text,
    sane_default text,
    values_list text,
    description text,
    disable_correlation boolean DEFAULT false NOT NULL,
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
    uuid character varying(40),
    name character varying(255),
    "meta-category" character varying(255),
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
    name character varying(255),
    "meta-category" character varying(255),
    description text,
    template_uuid character varying(40),
    template_version bigint NOT NULL,
    event_id bigint NOT NULL,
    uuid character varying(40),
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    distribution smallint DEFAULT '0'::smallint NOT NULL,
    sharing_group_id bigint,
    comment text NOT NULL,
    deleted boolean DEFAULT false NOT NULL
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
-- Name: org_blacklists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_blacklists (
    id bigint NOT NULL,
    org_uuid character varying(40) NOT NULL,
    created timestamp with time zone NOT NULL,
    org_name character varying(255) NOT NULL,
    comment text NOT NULL
);


--
-- Name: org_blacklists_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.org_blacklists_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: org_blacklists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.org_blacklists_id_seq OWNED BY public.org_blacklists.id;


--
-- Name: organisations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organisations (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    date_created timestamp with time zone NOT NULL,
    date_modified timestamp with time zone NOT NULL,
    description text,
    type character varying(255),
    nationality character varying(255),
    sector character varying(255),
    created_by bigint DEFAULT '0'::bigint NOT NULL,
    uuid character varying(40),
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
    perm_decaying boolean DEFAULT false NOT NULL
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
    organization character varying(10),
    remote_org_id bigint NOT NULL,
    publish_without_email boolean DEFAULT false NOT NULL,
    unpublish_event boolean DEFAULT false NOT NULL,
    self_signed boolean NOT NULL,
    pull_rules text NOT NULL,
    push_rules text NOT NULL,
    cert_file character varying(255),
    client_cert_file character varying(255),
    internal boolean DEFAULT false NOT NULL
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
    email character varying(255),
    event_org_id bigint NOT NULL,
    comment text NOT NULL,
    event_uuid character varying(40) NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    "timestamp" bigint DEFAULT '0'::bigint NOT NULL,
    proposal_to_delete boolean DEFAULT false NOT NULL,
    disable_correlation boolean DEFAULT false NOT NULL
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
-- Name: sightings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sightings (
    id bigint NOT NULL,
    attribute_id bigint NOT NULL,
    event_id bigint NOT NULL,
    org_id bigint NOT NULL,
    date_sighting numeric NOT NULL,
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
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tags (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    colour character varying(7) NOT NULL,
    exportable boolean NOT NULL,
    org_id boolean DEFAULT false NOT NULL,
    user_id bigint DEFAULT '0'::bigint NOT NULL,
    hide_tag boolean DEFAULT false NOT NULL
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
    process_id character varying(32),
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
    enabled boolean DEFAULT false NOT NULL
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
    colour character varying(7)
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
    colour character varying(7)
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
    description character varying(255),
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
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    password character varying(255) NOT NULL,
    org_id bigint NOT NULL,
    server_id bigint DEFAULT '0'::bigint NOT NULL,
    email character varying(255) NOT NULL,
    autoalert boolean DEFAULT false NOT NULL,
    authkey character varying(40),
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
    date_created numeric,
    date_modified numeric
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
    warninglist_entry_count bigint
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
-- Name: whitelist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.whitelist (
    id bigint NOT NULL,
    name text NOT NULL
);


--
-- Name: whitelist_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.whitelist_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: whitelist_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.whitelist_id_seq OWNED BY public.whitelist.id;


--
-- Name: admin_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_settings ALTER COLUMN id SET DEFAULT nextval('public.admin_settings_id_seq'::regclass);


--
-- Name: attribute_tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_tags ALTER COLUMN id SET DEFAULT nextval('public.attribute_tags_id_seq'::regclass);


--
-- Name: attributes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attributes ALTER COLUMN id SET DEFAULT nextval('public.attributes_id_seq'::regclass);


--
-- Name: correlations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlations ALTER COLUMN id SET DEFAULT nextval('public.correlations_id_seq'::regclass);


--
-- Name: event_blacklists id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_blacklists ALTER COLUMN id SET DEFAULT nextval('public.event_blacklists_id_seq'::regclass);


--
-- Name: event_delegations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_delegations ALTER COLUMN id SET DEFAULT nextval('public.event_delegations_id_seq'::regclass);


--
-- Name: event_locks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_locks ALTER COLUMN id SET DEFAULT nextval('public.event_locks_id_seq'::regclass);


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
-- Name: org_blacklists id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_blacklists ALTER COLUMN id SET DEFAULT nextval('public.org_blacklists_id_seq'::regclass);


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
-- Name: sightings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sightings ALTER COLUMN id SET DEFAULT nextval('public.sightings_id_seq'::regclass);


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
-- Name: whitelist id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.whitelist ALTER COLUMN id SET DEFAULT nextval('public.whitelist_id_seq'::regclass);


--
-- Name: admin_settings idx_20639_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_settings
    ADD CONSTRAINT idx_20639_primary PRIMARY KEY (id);


--
-- Name: attributes idx_20648_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attributes
    ADD CONSTRAINT idx_20648_primary PRIMARY KEY (id);


--
-- Name: attribute_tags idx_20663_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_tags
    ADD CONSTRAINT idx_20663_primary PRIMARY KEY (id);


--
-- Name: cake_sessions idx_20673_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cake_sessions
    ADD CONSTRAINT idx_20673_primary PRIMARY KEY (id);


--
-- Name: correlations idx_20682_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlations
    ADD CONSTRAINT idx_20682_primary PRIMARY KEY (id);


--
-- Name: events idx_20691_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT idx_20691_primary PRIMARY KEY (id);


--
-- Name: event_blacklists idx_20709_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_blacklists
    ADD CONSTRAINT idx_20709_primary PRIMARY KEY (id);


--
-- Name: event_delegations idx_20718_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_delegations
    ADD CONSTRAINT idx_20718_primary PRIMARY KEY (id);


--
-- Name: event_locks idx_20728_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_locks
    ADD CONSTRAINT idx_20728_primary PRIMARY KEY (id);


--
-- Name: event_tags idx_20735_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_tags
    ADD CONSTRAINT idx_20735_primary PRIMARY KEY (id);


--
-- Name: favourite_tags idx_20741_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.favourite_tags
    ADD CONSTRAINT idx_20741_primary PRIMARY KEY (id);


--
-- Name: feeds idx_20747_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feeds
    ADD CONSTRAINT idx_20747_primary PRIMARY KEY (id);


--
-- Name: fuzzy_correlate_ssdeep idx_20771_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fuzzy_correlate_ssdeep
    ADD CONSTRAINT idx_20771_primary PRIMARY KEY (id);


--
-- Name: galaxies idx_20777_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxies
    ADD CONSTRAINT idx_20777_primary PRIMARY KEY (id);


--
-- Name: galaxy_clusters idx_20789_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxy_clusters
    ADD CONSTRAINT idx_20789_primary PRIMARY KEY (id);


--
-- Name: galaxy_elements idx_20801_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxy_elements
    ADD CONSTRAINT idx_20801_primary PRIMARY KEY (id);


--
-- Name: galaxy_reference idx_20811_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.galaxy_reference
    ADD CONSTRAINT idx_20811_primary PRIMARY KEY (id);


--
-- Name: jobs idx_20820_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT idx_20820_primary PRIMARY KEY (id);


--
-- Name: logs idx_20833_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.logs
    ADD CONSTRAINT idx_20833_primary PRIMARY KEY (id);


--
-- Name: news idx_20845_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.news
    ADD CONSTRAINT idx_20845_primary PRIMARY KEY (id);


--
-- Name: noticelists idx_20854_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.noticelists
    ADD CONSTRAINT idx_20854_primary PRIMARY KEY (id);


--
-- Name: noticelist_entries idx_20865_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.noticelist_entries
    ADD CONSTRAINT idx_20865_primary PRIMARY KEY (id);


--
-- Name: objects idx_20874_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.objects
    ADD CONSTRAINT idx_20874_primary PRIMARY KEY (id);


--
-- Name: object_references idx_20886_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_references
    ADD CONSTRAINT idx_20886_primary PRIMARY KEY (id);


--
-- Name: object_relationships idx_20898_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_relationships
    ADD CONSTRAINT idx_20898_primary PRIMARY KEY (id);


--
-- Name: object_templates idx_20907_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_templates
    ADD CONSTRAINT idx_20907_primary PRIMARY KEY (id);


--
-- Name: object_template_elements idx_20918_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.object_template_elements
    ADD CONSTRAINT idx_20918_primary PRIMARY KEY (id);


--
-- Name: organisations idx_20929_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organisations
    ADD CONSTRAINT idx_20929_primary PRIMARY KEY (id);


--
-- Name: org_blacklists idx_20940_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_blacklists
    ADD CONSTRAINT idx_20940_primary PRIMARY KEY (id);


--
-- Name: posts idx_20949_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posts
    ADD CONSTRAINT idx_20949_primary PRIMARY KEY (id);


--
-- Name: regexp idx_20960_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.regexp
    ADD CONSTRAINT idx_20960_primary PRIMARY KEY (id);


--
-- Name: roles idx_20970_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT idx_20970_primary PRIMARY KEY (id);


--
-- Name: servers idx_20994_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.servers
    ADD CONSTRAINT idx_20994_primary PRIMARY KEY (id);


--
-- Name: shadow_attributes idx_21006_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shadow_attributes
    ADD CONSTRAINT idx_21006_primary PRIMARY KEY (id);


--
-- Name: shadow_attribute_correlations idx_21021_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shadow_attribute_correlations
    ADD CONSTRAINT idx_21021_primary PRIMARY KEY (id);


--
-- Name: sharing_groups idx_21030_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sharing_groups
    ADD CONSTRAINT idx_21030_primary PRIMARY KEY (id);


--
-- Name: sharing_group_orgs idx_21041_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sharing_group_orgs
    ADD CONSTRAINT idx_21041_primary PRIMARY KEY (id);


--
-- Name: sharing_group_servers idx_21048_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sharing_group_servers
    ADD CONSTRAINT idx_21048_primary PRIMARY KEY (id);


--
-- Name: sightings idx_21054_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sightings
    ADD CONSTRAINT idx_21054_primary PRIMARY KEY (id);


--
-- Name: tags idx_21066_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT idx_21066_primary PRIMARY KEY (id);


--
-- Name: tasks idx_21075_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT idx_21075_primary PRIMARY KEY (id);


--
-- Name: taxonomies idx_21085_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.taxonomies
    ADD CONSTRAINT idx_21085_primary PRIMARY KEY (id);


--
-- Name: taxonomy_entries idx_21095_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.taxonomy_entries
    ADD CONSTRAINT idx_21095_primary PRIMARY KEY (id);


--
-- Name: taxonomy_predicates idx_21104_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.taxonomy_predicates
    ADD CONSTRAINT idx_21104_primary PRIMARY KEY (id);


--
-- Name: templates idx_21113_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.templates
    ADD CONSTRAINT idx_21113_primary PRIMARY KEY (id);


--
-- Name: template_elements idx_21122_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_elements
    ADD CONSTRAINT idx_21122_primary PRIMARY KEY (id);


--
-- Name: template_element_attributes idx_21128_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_element_attributes
    ADD CONSTRAINT idx_21128_primary PRIMARY KEY (id);


--
-- Name: template_element_files idx_21138_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_element_files
    ADD CONSTRAINT idx_21138_primary PRIMARY KEY (id);


--
-- Name: template_element_texts idx_21147_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_element_texts
    ADD CONSTRAINT idx_21147_primary PRIMARY KEY (id);


--
-- Name: template_tags idx_21156_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.template_tags
    ADD CONSTRAINT idx_21156_primary PRIMARY KEY (id);


--
-- Name: threads idx_21162_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threads
    ADD CONSTRAINT idx_21162_primary PRIMARY KEY (id);


--
-- Name: threat_levels idx_21168_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_levels
    ADD CONSTRAINT idx_21168_primary PRIMARY KEY (id);


--
-- Name: users idx_21177_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT idx_21177_primary PRIMARY KEY (id);


--
-- Name: warninglists idx_21199_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.warninglists
    ADD CONSTRAINT idx_21199_primary PRIMARY KEY (id);


--
-- Name: warninglist_entries idx_21211_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.warninglist_entries
    ADD CONSTRAINT idx_21211_primary PRIMARY KEY (id);


--
-- Name: warninglist_types idx_21220_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.warninglist_types
    ADD CONSTRAINT idx_21220_primary PRIMARY KEY (id);


--
-- Name: whitelist idx_21226_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.whitelist
    ADD CONSTRAINT idx_21226_primary PRIMARY KEY (id);


--
-- Name: idx_20648_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20648_category ON public.attributes USING btree (category);


--
-- Name: idx_20648_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20648_event_id ON public.attributes USING btree (event_id);


--
-- Name: idx_20648_object_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20648_object_id ON public.attributes USING btree (object_id);


--
-- Name: idx_20648_object_relation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20648_object_relation ON public.attributes USING btree (object_relation);


--
-- Name: idx_20648_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20648_sharing_group_id ON public.attributes USING btree (sharing_group_id);


--
-- Name: idx_20648_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20648_type ON public.attributes USING btree (type);


--
-- Name: idx_20648_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_20648_uuid ON public.attributes USING btree (uuid);


--
-- Name: idx_20648_value1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20648_value1 ON public.attributes USING btree (value1);


--
-- Name: idx_20648_value2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20648_value2 ON public.attributes USING btree (value2);


--
-- Name: idx_20663_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20663_attribute_id ON public.attribute_tags USING btree (attribute_id);


--
-- Name: idx_20663_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20663_event_id ON public.attribute_tags USING btree (event_id);


--
-- Name: idx_20663_tag_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20663_tag_id ON public.attribute_tags USING btree (tag_id);


--
-- Name: idx_20673_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20673_expires ON public.cake_sessions USING btree (expires);


--
-- Name: idx_20682_1_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20682_1_attribute_id ON public.correlations USING btree ("1_attribute_id");


--
-- Name: idx_20682_1_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20682_1_event_id ON public.correlations USING btree ("1_event_id");


--
-- Name: idx_20682_a_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20682_a_sharing_group_id ON public.correlations USING btree (a_sharing_group_id);


--
-- Name: idx_20682_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20682_attribute_id ON public.correlations USING btree (attribute_id);


--
-- Name: idx_20682_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20682_event_id ON public.correlations USING btree (event_id);


--
-- Name: idx_20682_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20682_org_id ON public.correlations USING btree (org_id);


--
-- Name: idx_20682_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20682_sharing_group_id ON public.correlations USING btree (sharing_group_id);


--
-- Name: idx_20682_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20682_value ON public.correlations USING btree (value);


--
-- Name: idx_20691_extends_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20691_extends_uuid ON public.events USING btree (extends_uuid);


--
-- Name: idx_20691_info; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20691_info ON public.events USING btree (info);


--
-- Name: idx_20691_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20691_org_id ON public.events USING btree (org_id);


--
-- Name: idx_20691_orgc_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20691_orgc_id ON public.events USING btree (orgc_id);


--
-- Name: idx_20691_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20691_sharing_group_id ON public.events USING btree (sharing_group_id);


--
-- Name: idx_20691_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_20691_uuid ON public.events USING btree (uuid);


--
-- Name: idx_20709_event_orgc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20709_event_orgc ON public.event_blacklists USING btree (event_orgc);


--
-- Name: idx_20709_event_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20709_event_uuid ON public.event_blacklists USING btree (event_uuid);


--
-- Name: idx_20718_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20718_event_id ON public.event_delegations USING btree (event_id);


--
-- Name: idx_20718_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20718_org_id ON public.event_delegations USING btree (org_id);


--
-- Name: idx_20728_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20728_event_id ON public.event_locks USING btree (event_id);


--
-- Name: idx_20728_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20728_timestamp ON public.event_locks USING btree ("timestamp");


--
-- Name: idx_20728_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20728_user_id ON public.event_locks USING btree (user_id);


--
-- Name: idx_20735_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20735_event_id ON public.event_tags USING btree (event_id);


--
-- Name: idx_20735_tag_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20735_tag_id ON public.event_tags USING btree (tag_id);


--
-- Name: idx_20741_tag_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20741_tag_id ON public.favourite_tags USING btree (tag_id);


--
-- Name: idx_20741_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20741_user_id ON public.favourite_tags USING btree (user_id);


--
-- Name: idx_20747_input_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20747_input_source ON public.feeds USING btree (input_source);


--
-- Name: idx_20771_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20771_attribute_id ON public.fuzzy_correlate_ssdeep USING btree (attribute_id);


--
-- Name: idx_20771_chunk; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20771_chunk ON public.fuzzy_correlate_ssdeep USING btree (chunk);


--
-- Name: idx_20777_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20777_name ON public.galaxies USING btree (name);


--
-- Name: idx_20777_namespace; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20777_namespace ON public.galaxies USING btree (namespace);


--
-- Name: idx_20777_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20777_type ON public.galaxies USING btree (type);


--
-- Name: idx_20777_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20777_uuid ON public.galaxies USING btree (uuid);


--
-- Name: idx_20789_galaxy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20789_galaxy_id ON public.galaxy_clusters USING btree (galaxy_id);


--
-- Name: idx_20789_tag_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20789_tag_name ON public.galaxy_clusters USING btree (tag_name);


--
-- Name: idx_20789_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20789_type ON public.galaxy_clusters USING btree (type);


--
-- Name: idx_20789_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20789_uuid ON public.galaxy_clusters USING btree (uuid);


--
-- Name: idx_20789_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20789_value ON public.galaxy_clusters USING btree (value);


--
-- Name: idx_20789_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20789_version ON public.galaxy_clusters USING btree (version);


--
-- Name: idx_20801_galaxy_cluster_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20801_galaxy_cluster_id ON public.galaxy_elements USING btree (galaxy_cluster_id);


--
-- Name: idx_20801_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20801_key ON public.galaxy_elements USING btree (key);


--
-- Name: idx_20801_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20801_value ON public.galaxy_elements USING btree (value);


--
-- Name: idx_20811_galaxy_cluster_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20811_galaxy_cluster_id ON public.galaxy_reference USING btree (galaxy_cluster_id);


--
-- Name: idx_20811_referenced_galaxy_cluster_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20811_referenced_galaxy_cluster_id ON public.galaxy_reference USING btree (referenced_galaxy_cluster_id);


--
-- Name: idx_20811_referenced_galaxy_cluster_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20811_referenced_galaxy_cluster_type ON public.galaxy_reference USING btree (referenced_galaxy_cluster_type);


--
-- Name: idx_20811_referenced_galaxy_cluster_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20811_referenced_galaxy_cluster_value ON public.galaxy_reference USING btree (referenced_galaxy_cluster_value);


--
-- Name: idx_20854_geographical_area; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20854_geographical_area ON public.noticelists USING btree (geographical_area);


--
-- Name: idx_20854_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20854_name ON public.noticelists USING btree (name);


--
-- Name: idx_20865_noticelist_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20865_noticelist_id ON public.noticelist_entries USING btree (noticelist_id);


--
-- Name: idx_20874_distribution; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20874_distribution ON public.objects USING btree (distribution);


--
-- Name: idx_20874_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20874_event_id ON public.objects USING btree (event_id);


--
-- Name: idx_20874_meta-category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_20874_meta-category" ON public.objects USING btree ("meta-category");


--
-- Name: idx_20874_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20874_name ON public.objects USING btree (name);


--
-- Name: idx_20874_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20874_sharing_group_id ON public.objects USING btree (sharing_group_id);


--
-- Name: idx_20874_template_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20874_template_uuid ON public.objects USING btree (template_uuid);


--
-- Name: idx_20874_template_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20874_template_version ON public.objects USING btree (template_version);


--
-- Name: idx_20874_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20874_timestamp ON public.objects USING btree ("timestamp");


--
-- Name: idx_20874_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20874_uuid ON public.objects USING btree (uuid);


--
-- Name: idx_20886_object_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20886_object_id ON public.object_references USING btree (object_id);


--
-- Name: idx_20886_referenced_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20886_referenced_id ON public.object_references USING btree (referenced_id);


--
-- Name: idx_20886_referenced_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20886_referenced_uuid ON public.object_references USING btree (referenced_uuid);


--
-- Name: idx_20886_relationship_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20886_relationship_type ON public.object_references USING btree (relationship_type);


--
-- Name: idx_20886_source_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20886_source_uuid ON public.object_references USING btree (source_uuid);


--
-- Name: idx_20886_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20886_timestamp ON public.object_references USING btree ("timestamp");


--
-- Name: idx_20898_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20898_name ON public.object_relationships USING btree (name);


--
-- Name: idx_20907_meta-category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_20907_meta-category" ON public.object_templates USING btree ("meta-category");


--
-- Name: idx_20907_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20907_name ON public.object_templates USING btree (name);


--
-- Name: idx_20907_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20907_org_id ON public.object_templates USING btree (org_id);


--
-- Name: idx_20907_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20907_user_id ON public.object_templates USING btree (user_id);


--
-- Name: idx_20907_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20907_uuid ON public.object_templates USING btree (uuid);


--
-- Name: idx_20918_object_relation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20918_object_relation ON public.object_template_elements USING btree (object_relation);


--
-- Name: idx_20918_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20918_type ON public.object_template_elements USING btree (type);


--
-- Name: idx_20929_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20929_name ON public.organisations USING btree (name);


--
-- Name: idx_20929_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20929_uuid ON public.organisations USING btree (uuid);


--
-- Name: idx_20949_post_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20949_post_id ON public.posts USING btree (post_id);


--
-- Name: idx_20949_thread_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20949_thread_id ON public.posts USING btree (thread_id);


--
-- Name: idx_20994_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20994_org_id ON public.servers USING btree (org_id);


--
-- Name: idx_20994_remote_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_20994_remote_org_id ON public.servers USING btree (remote_org_id);


--
-- Name: idx_21006_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21006_category ON public.shadow_attributes USING btree (category);


--
-- Name: idx_21006_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21006_event_id ON public.shadow_attributes USING btree (event_id);


--
-- Name: idx_21006_event_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21006_event_org_id ON public.shadow_attributes USING btree (event_org_id);


--
-- Name: idx_21006_event_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21006_event_uuid ON public.shadow_attributes USING btree (event_uuid);


--
-- Name: idx_21006_old_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21006_old_id ON public.shadow_attributes USING btree (old_id);


--
-- Name: idx_21006_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21006_type ON public.shadow_attributes USING btree (type);


--
-- Name: idx_21006_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21006_uuid ON public.shadow_attributes USING btree (uuid);


--
-- Name: idx_21006_value1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21006_value1 ON public.shadow_attributes USING btree (value1);


--
-- Name: idx_21006_value2; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21006_value2 ON public.shadow_attributes USING btree (value2);


--
-- Name: idx_21021_1_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21021_1_event_id ON public.shadow_attribute_correlations USING btree ("1_event_id");


--
-- Name: idx_21021_1_shadow_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21021_1_shadow_attribute_id ON public.shadow_attribute_correlations USING btree ("1_shadow_attribute_id");


--
-- Name: idx_21021_a_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21021_a_sharing_group_id ON public.shadow_attribute_correlations USING btree (a_sharing_group_id);


--
-- Name: idx_21021_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21021_attribute_id ON public.shadow_attribute_correlations USING btree (attribute_id);


--
-- Name: idx_21021_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21021_event_id ON public.shadow_attribute_correlations USING btree (event_id);


--
-- Name: idx_21021_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21021_org_id ON public.shadow_attribute_correlations USING btree (org_id);


--
-- Name: idx_21021_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21021_sharing_group_id ON public.shadow_attribute_correlations USING btree (sharing_group_id);


--
-- Name: idx_21030_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21030_org_id ON public.sharing_groups USING btree (org_id);


--
-- Name: idx_21030_organisation_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21030_organisation_uuid ON public.sharing_groups USING btree (organisation_uuid);


--
-- Name: idx_21030_sync_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21030_sync_user_id ON public.sharing_groups USING btree (sync_user_id);


--
-- Name: idx_21030_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_21030_uuid ON public.sharing_groups USING btree (uuid);


--
-- Name: idx_21041_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21041_org_id ON public.sharing_group_orgs USING btree (org_id);


--
-- Name: idx_21041_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21041_sharing_group_id ON public.sharing_group_orgs USING btree (sharing_group_id);


--
-- Name: idx_21048_server_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21048_server_id ON public.sharing_group_servers USING btree (server_id);


--
-- Name: idx_21048_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21048_sharing_group_id ON public.sharing_group_servers USING btree (sharing_group_id);


--
-- Name: idx_21054_attribute_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21054_attribute_id ON public.sightings USING btree (attribute_id);


--
-- Name: idx_21054_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21054_event_id ON public.sightings USING btree (event_id);


--
-- Name: idx_21054_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21054_org_id ON public.sightings USING btree (org_id);


--
-- Name: idx_21054_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21054_source ON public.sightings USING btree (source);


--
-- Name: idx_21054_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21054_type ON public.sightings USING btree (type);


--
-- Name: idx_21054_uuid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21054_uuid ON public.sightings USING btree (uuid);


--
-- Name: idx_21066_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21066_name ON public.tags USING btree (name);


--
-- Name: idx_21066_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21066_org_id ON public.tags USING btree (org_id);


--
-- Name: idx_21066_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21066_user_id ON public.tags USING btree (user_id);


--
-- Name: idx_21095_taxonomy_predicate_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21095_taxonomy_predicate_id ON public.taxonomy_entries USING btree (taxonomy_predicate_id);


--
-- Name: idx_21104_taxonomy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21104_taxonomy_id ON public.taxonomy_predicates USING btree (taxonomy_id);


--
-- Name: idx_21162_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21162_event_id ON public.threads USING btree (event_id);


--
-- Name: idx_21162_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21162_org_id ON public.threads USING btree (org_id);


--
-- Name: idx_21162_sharing_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21162_sharing_group_id ON public.threads USING btree (sharing_group_id);


--
-- Name: idx_21162_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21162_user_id ON public.threads USING btree (user_id);


--
-- Name: idx_21177_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21177_email ON public.users USING btree (email);


--
-- Name: idx_21177_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21177_org_id ON public.users USING btree (org_id);


--
-- Name: idx_21177_server_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21177_server_id ON public.users USING btree (server_id);


--
-- Name: idx_21211_warninglist_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21211_warninglist_id ON public.warninglist_entries USING btree (warninglist_id);


--
-- PostgreSQL database dump complete
--

