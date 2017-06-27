-- --------------------------------------------------------

--
-- Table structure for table admin_settings
--

CREATE TABLE IF NOT EXISTS admin_settings (
  id bigserial NOT NULL,
  setting varchar(255) NOT NULL,
  value text NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table attributes
--

CREATE TABLE IF NOT EXISTS attributes (
  id bigserial NOT NULL,
  event_id bigint NOT NULL,
  category varchar(255) NOT NULL,
  type varchar(100) NOT NULL,
  value1 text NOT NULL,
  value2 text NOT NULL,
  to_ids smallint NOT NULL DEFAULT 1,
  uuid varchar(40) NOT NULL,
  timestamp bigint NOT NULL DEFAULT 0,
  distribution smallint NOT NULL DEFAULT 0,
  sharing_group_id bigint NOT NULL,
  comment text DEFAULT "",
  deleted smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE (uuid)
);
CREATE INDEX idx_attributes_event_id ON attributes (event_id);
CREATE INDEX idx_attributes_sharing_group_id ON attributes (sharing_group_id);
CREATE INDEX idx_attributes_value1 ON attributes (value1);
CREATE INDEX idx_attributes_value2 ON attributes (value2);

-- -------------------------------------------------------

--
-- Table structure for table attribute_tags
--

CREATE TABLE IF NOT EXISTS attribute_tags (
  id bigserial NOT NULL,
  attribute_id bigint NOT NULL,
  event_id bigint NOT NULL,
  tag_id bigint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_attribute_tags_attribute_id ON attribute_tags (attribute_id);
CREATE INDEX idx_attribute_tags_event_id ON attribute_tags (event_id);
CREATE INDEX idx_attribute_tags_tag_id ON attribute_tags (tag_id);

-- --------------------------------------------------------

--
-- Table structure for table bruteforces
--

CREATE TABLE IF NOT EXISTS bruteforces (
  ip varchar(255) NOT NULL,
  username varchar(255) NOT NULL,
  expire timestamp NOT NULL
);

-- --------------------------------------------------------

--
-- Table structure for table cake_sessions
--

CREATE TABLE IF NOT EXISTS cake_sessions (
  id varchar(255) NOT NULL DEFAULT '',
  data text NOT NULL,
  expires bigint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_cake_sessions_expires ON cake_sessions (expires);

-- --------------------------------------------------------

--
-- Table structure for table correlations
--

CREATE TABLE IF NOT EXISTS correlations (
  id bigserial NOT NULL,
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
  info text NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_correlations_event_id ON correlations (event_id);
CREATE INDEX idx_correlations_1_event_id ON correlations ("1_event_id");
CREATE INDEX idx_correlations_attribute_id ON correlations (attribute_id);
CREATE INDEX idx_correlations_1_attribute_id ON correlations ("1_attribute_id");
CREATE INDEX idx_correlations_org_id ON correlations (org_id);
CREATE INDEX idx_correlations_sharing_group_id ON correlations (sharing_group_id);
CREATE INDEX idx_correlations_a_sharing_group_id ON correlations (a_sharing_group_id);

-- --------------------------------------------------------

--
-- Table structure for table events
--

CREATE TABLE IF NOT EXISTS events (
  id bigserial NOT NULL,
  org_id bigint NOT NULL,
  date date NOT NULL,
  info text NOT NULL,
  user_id bigint NOT NULL,
  uuid varchar(40) NOT NULL,
  published smallint NOT NULL DEFAULT 0,
  analysis smallint NOT NULL,
  attribute_count bigint CHECK (attribute_count >= 0) DEFAULT NULL,
  orgc_id bigint NOT NULL,
  timestamp bigint NOT NULL DEFAULT 0,
  distribution smallint NOT NULL DEFAULT 0,
  sharing_group_id bigint NOT NULL,
  proposal_email_lock smallint NOT NULL DEFAULT 0,
  locked smallint NOT NULL DEFAULT 0,
  threat_level_id bigint NOT NULL,
  publish_timestamp bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE (uuid)
);
CREATE INDEX idx_events_info ON events (info);
CREATE INDEX idx_events_sharing_group_id ON events (sharing_group_id);
CREATE INDEX idx_events_org_id ON events (org_id);
CREATE INDEX idx_events_orgc_id ON events (orgc_id);

-- -------------------------------------------------------

--
-- Table structure for event_blacklists
--

CREATE TABLE event_blacklists (
  id bigserial NOT NULL,
  event_uuid varchar(40) NOT NULL,
  created timestamp NOT NULL,
  event_info text NOT NULL,
  comment text NOT NULL,
  event_orgc varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

-- -------------------------------------------------------

--
-- Table structure for event_delegations
--

CREATE TABLE IF NOT EXISTS event_delegations (
  id bigserial NOT NULL,
  org_id bigint NOT NULL,
  requester_org_id bigint NOT NULL,
  event_id bigint NOT NULL,
  message text,
  distribution smallint NOT NULL DEFAULT -1,
  sharing_group_id bigint,
  PRIMARY KEY (id)
);
CREATE INDEX idx_event_delegations_org_id ON event_delegations (org_id);
CREATE INDEX idx_event_delegations_event_id ON event_delegations (event_id);

-- -------------------------------------------------------

--
-- Table structure for event_tags
--

CREATE TABLE IF NOT EXISTS event_tags (
  id bigserial NOT NULL,
  event_id bigint NOT NULL,
  tag_id bigint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_event_tags_event_id ON event_tags (event_id);
CREATE INDEX idx_event_tags_tag_id ON event_tags (tag_id);

-- -------------------------------------------------------

--
-- Table structure for favourite_tags
--

CREATE TABLE IF NOT EXISTS favourite_tags (
  id bigserial NOT NULL,
  tag_id bigint NOT NULL,
  user_id bigint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_favourite_tags_user_id ON favourite_tags (user_id);
CREATE INDEX idx_favourite_tags_tag_id ON favourite_tags (tag_id);

-- -------------------------------------------------------

--
-- Table structure for feeds
--

CREATE TABLE IF NOT EXISTS feeds (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  provider varchar(255) NOT NULL,
  url varchar(255) NOT NULL,
  rules text DEFAULT NULL,
  enabled smallint NOT NULL,
  distribution smallint NOT NULL,
  sharing_group_id bigint NOT NULL DEFAULT 0,
  tag_id bigint NOT NULL DEFAULT 0,
  "default" smallint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table jobs
--

CREATE TABLE IF NOT EXISTS jobs (
  id bigserial NOT NULL,
  worker varchar(32) NOT NULL,
  job_type varchar(32) NOT NULL,
  job_input text NOT NULL,
  status smallint NOT NULL DEFAULT 0,
  retries bigint NOT NULL DEFAULT 0,
  message text NOT NULL,
  progress bigint NOT NULL DEFAULT 0,
  org_id bigint NOT NULL DEFAULT 0,
  process_id varchar(32) DEFAULT NULL,
  date_created timestamp NOT NULL,
  date_modified timestamp NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table logs
--

CREATE TABLE IF NOT EXISTS logs (
  id bigserial NOT NULL,
  title text DEFAULT NULL,
  created timestamp NOT NULL,
  model varchar(20) NOT NULL,
  model_id bigint NOT NULL,
  action varchar(20) NOT NULL,
  user_id bigint NOT NULL,
  change text DEFAULT NULL,
  email varchar(255) NOT NULL,
  org varchar(255) NOT NULL,
  description text DEFAULT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table news
--

CREATE TABLE IF NOT EXISTS news (
  id bigserial NOT NULL,
  message text NOT NULL,
  title text NOT NULL,
  user_id bigint NOT NULL,
  date_created bigint NOT NULL,
  PRIMARY KEY (id)
);

-- -------------------------------------------------------

--
-- Table structure for org_blacklists
--

CREATE TABLE org_blacklists (
 id bigserial NOT NULL,
 org_uuid varchar(40) NOT NULL,
 created timestamp NOT NULL,
 org_name varchar(255) NOT NULL,
 comment text NOT NULL,
 PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table organisations
--

CREATE TABLE organisations (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  date_created timestamp NOT NULL,
  date_modified timestamp NOT NULL,
  description text,
  type varchar(255),
  nationality varchar(255),
  sector varchar(255),
  created_by bigint NOT NULL DEFAULT 0,
  uuid varchar(40) DEFAULT NULL,
  contacts text,
  local smallint NOT NULL DEFAULT 0,
  landingpage text,
  PRIMARY KEY (id)
);
CREATE INDEX idx_organisations_uuid ON organisations (uuid);
CREATE INDEX idx_organisations_name ON organisations (name);

-- --------------------------------------------------------

--
-- Table structure for table posts
--

CREATE TABLE IF NOT EXISTS posts (
  id bigserial NOT NULL,
  date_created timestamp NOT NULL,
  date_modified timestamp NOT NULL,
  user_id bigint NOT NULL,
  contents text NOT NULL,
  post_id bigint NOT NULL DEFAULT 0,
  thread_id bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);
CREATE INDEX idx_posts_post_id ON posts (post_id);
CREATE INDEX idx_posts_thread_id ON posts (thread_id);

-- --------------------------------------------------------

--
-- Table structure for table regexp
--

CREATE TABLE IF NOT EXISTS regexp (
  id bigserial NOT NULL,
  regexp varchar(255) NOT NULL,
  replacement varchar(255) NOT NULL,
  type varchar(100) NOT NULL DEFAULT 'ALL',
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table roles
--

CREATE TABLE IF NOT EXISTS roles (
  id bigserial NOT NULL,
  name varchar(100) NOT NULL,
  created timestamp DEFAULT NULL,
  modified timestamp DEFAULT NULL,
  perm_add smallint DEFAULT NULL,
  perm_modify smallint DEFAULT NULL,
  perm_modify_org smallint DEFAULT NULL,
  perm_publish smallint DEFAULT NULL,
  perm_delegate smallint NOT NULL DEFAULT 0,
  perm_sync smallint DEFAULT NULL,
  perm_admin smallint DEFAULT NULL,
  perm_audit smallint DEFAULT NULL,
  perm_full smallint DEFAULT NULL,
  perm_auth smallint NOT NULL DEFAULT 0,
  perm_site_admin smallint NOT NULL DEFAULT 0,
  perm_regexp_access smallint NOT NULL DEFAULT 0,
  perm_tagger smallint NOT NULL DEFAULT 0,
  perm_template smallint NOT NULL DEFAULT 0,
  perm_sharing_group smallint NOT NULL DEFAULT 0,
  perm_tag_editor smallint NOT NULL DEFAULT 0,
  default_role smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table servers
--

CREATE TABLE IF NOT EXISTS servers (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  url varchar(255) NOT NULL,
  authkey varchar(40) NOT NULL,
  org_id bigint NOT NULL,
  push smallint NOT NULL,
  pull smallint NOT NULL,
  lastpulledid bigint DEFAULT NULL,
  lastpushedid bigint DEFAULT NULL,
  organization varchar(10) DEFAULT NULL,
  remote_org_id bigint NOT NULL,
  publish_without_email smallint NOT NULL DEFAULT 0,
  unpublish_event smallint NOT NULL DEFAULT 0,
  self_signed smallint NOT NULL,
  pull_rules text NOT NULL,
  push_rules text NOT NULL,
  cert_file varchar(255) DEFAULT NULL,
  client_cert_file varchar(255) DEFAULT NULL,
  internal smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);
CREATE INDEX idx_servers_org_id ON servers (org_id);
CREATE INDEX idx_servers_remote_org_id ON servers (remote_org_id);

-- --------------------------------------------------------

--
-- Table structure for table shadow_attributes
--

CREATE TABLE IF NOT EXISTS shadow_attributes (
  id bigserial NOT NULL,
  old_id bigint NOT NULL,
  event_id bigint NOT NULL,
  type varchar(100) NOT NULL,
  category varchar(255) NOT NULL,
  value1 text,
  to_ids smallint NOT NULL DEFAULT 1,
  uuid varchar(40) NOT NULL,
  value2 text,
  org_id bigint NOT NULL,
  email varchar(255) DEFAULT NULL,
  event_org_id bigint NOT NULL,
  comment text NOT NULL,
  event_uuid varchar(40) NOT NULL,
  deleted smallint NOT NULL DEFAULT 0,
  timestamp bigint NOT NULL DEFAULT 0,
  proposal_to_delete BOOLEAN NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_shadow_attributes_event_id ON shadow_attributes (event_id);
CREATE INDEX idx_shadow_attributes_event_uuid ON shadow_attributes (event_uuid);
CREATE INDEX idx_shadow_attributes_event_org_id ON shadow_attributes (event_org_id);
CREATE INDEX idx_shadow_attributes_uuid ON shadow_attributes (uuid);
CREATE INDEX idx_shadow_attributes_old_id ON shadow_attributes (old_id);
CREATE INDEX idx_shadow_attributes_value1 ON shadow_attributes (value1);
CREATE INDEX idx_shadow_attributes_value2 ON shadow_attributes (value2);

-- --------------------------------------------------------

--
-- Table structure for table shadow_attribute_correlations
--

CREATE TABLE IF NOT EXISTS shadow_attribute_correlations (
  id bigserial NOT NULL,
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
  info text NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_shadow_attribute_correlations_org_id ON shadow_attribute_correlations (org_id);
CREATE INDEX idx_shadow_attribute_correlations_attribute_id ON shadow_attribute_correlations (attribute_id);
CREATE INDEX idx_shadow_attribute_correlations_a_sharing_group_id ON shadow_attribute_correlations (a_sharing_group_id);
CREATE INDEX idx_shadow_attribute_correlations_event_id ON shadow_attribute_correlations (event_id);
CREATE INDEX idx_shadow_attribute_correlations_1_event_id ON shadow_attribute_correlations ("1_event_id");
CREATE INDEX idx_shadow_attribute_correlations_sharing_group_id ON shadow_attribute_correlations (sharing_group_id);
CREATE INDEX idx_shadow_attribute_correlations_1_shadow_attribute_id ON shadow_attribute_correlations ("1_shadow_attribute_id");

-- --------------------------------------------------------

--
-- Table structure for table sharing_group_orgs
--

CREATE TABLE sharing_group_orgs (
  id bigserial NOT NULL,
  sharing_group_id bigint NOT NULL,
  org_id bigint NOT NULL,
  extend smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);
CREATE INDEX idx_sharing_group_orgs_org_id ON sharing_group_orgs (org_id);
CREATE INDEX idx_sharing_group_orgs_sharing_group_id ON sharing_group_orgs (sharing_group_id);

-- --------------------------------------------------------

--
-- Table structure for table sharing_group_servers
--

CREATE TABLE sharing_group_servers (
  id bigserial NOT NULL,
  sharing_group_id bigint NOT NULL,
  server_id bigint NOT NULL,
  all_orgs smallint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_sharing_group_servers_server_id ON sharing_group_servers (server_id);
CREATE INDEX idx_sharing_group_servers_sharing_group_id ON sharing_group_servers (sharing_group_id);

-- --------------------------------------------------------

--
-- Table structure for table sharing_groups
--

CREATE TABLE sharing_groups (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  releasability text NOT NULL,
  description text NOT NULL,
  uuid varchar(40) NOT NULL,
  organisation_uuid varchar(40) NOT NULL,
  org_id bigint NOT NULL,
  sync_user_id bigint NOT NULL DEFAULT 0,
  active smallint NOT NULL,
  created timestamp NOT NULL,
  modified timestamp NOT NULL,
  local smallint NOT NULL,
  roaming smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE (uuid)
);
CREATE INDEX idx_sharing_groups_org_id ON sharing_groups (org_id);
CREATE INDEX idx_sharing_groups_sync_user_id ON sharing_groups (sync_user_id);
CREATE INDEX idx_sharing_groups_organisation_uuid ON sharing_groups (organisation_uuid);

-- --------------------------------------------------------

--
-- Table structure for table sightings
--

CREATE TABLE IF NOT EXISTS sightings (
  id bigserial NOT NULL,
  attribute_id bigint NOT NULL,
  event_id bigint NOT NULL,
  org_id bigint NOT NULL,
  date_sighting bigint NOT NULL,
  PRIMARY KEY (id)
);

CREATE INDEX idx_sightings_attribute_id ON sightings (attribute_id);
CREATE INDEX idx_sightings_event_id ON sightings (event_id);
CREATE INDEX idx_sightings_org_id ON sightings (org_id);

-- --------------------------------------------------------

--
-- Table structure for table tags
--

CREATE TABLE IF NOT EXISTS tags (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  colour varchar(7) NOT NULL,
  exportable smallint NOT NULL,
  org_id smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);
CREATE INDEX idx_tags_org_id ON tags (org_id);


-- --------------------------------------------------------

--
-- Table structure for table tasks
--

CREATE TABLE IF NOT EXISTS tasks (
  id bigserial NOT NULL,
  type varchar(100) NOT NULL,
  timer bigint NOT NULL,
  scheduled_time varchar(8) NOT NULL DEFAULT '6:00',
  process_id varchar(32) DEFAULT NULL,
  description varchar(255) NOT NULL,
  next_execution_time bigint NOT NULL,
  message varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table taxonomies
--

CREATE TABLE IF NOT EXISTS taxonomies (
  id bigserial NOT NULL,
  namespace varchar(255) NOT NULL,
  description text NOT NULL,
  version bigint NOT NULL,
  enabled smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table taxonomy_entries
--

CREATE TABLE IF NOT EXISTS taxonomy_entries (
  id bigserial NOT NULL,
  taxonomy_predicate_id bigint NOT NULL,
  value text NOT NULL,
  expanded text,
  colour varchar(7) NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_taxonomy_entries_taxonomy_predicate_id ON taxonomy_entries (taxonomy_predicate_id);

-- --------------------------------------------------------

--
-- Table structure for table taxonomy_predicates
--

CREATE TABLE IF NOT EXISTS taxonomy_predicates (
  id bigserial NOT NULL,
  taxonomy_id bigint NOT NULL,
  value text NOT NULL,
  expanded text,
  colour varchar(7) NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_taxonomy_predicates_taxonomy_id ON taxonomy_predicates (taxonomy_id);

-- --------------------------------------------------------

--
-- Table structure for table templates
--

CREATE TABLE IF NOT EXISTS templates (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  description varchar(255) NOT NULL,
  org varchar(255) NOT NULL,
  share smallint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_elements
--

CREATE TABLE IF NOT EXISTS template_elements (
  id bigserial NOT NULL,
  template_id bigint NOT NULL,
  position bigint NOT NULL,
  element_definition varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_element_attributes
--

CREATE TABLE IF NOT EXISTS template_element_attributes (
  id bigserial NOT NULL,
  template_element_id bigint NOT NULL,
  name varchar(255) NOT NULL,
  description text NOT NULL,
  to_ids smallint NOT NULL DEFAULT 1,
  category varchar(255) NOT NULL,
  complex smallint NOT NULL,
  type varchar(255) NOT NULL,
  mandatory smallint NOT NULL,
  batch smallint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_element_files
--

CREATE TABLE IF NOT EXISTS template_element_files (
  id bigserial NOT NULL,
  template_element_id bigint NOT NULL,
  name varchar(255) NOT NULL,
  description text NOT NULL,
  category varchar(255) NOT NULL,
  malware smallint NOT NULL,
  mandatory smallint NOT NULL,
  batch smallint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_element_texts
--

CREATE TABLE IF NOT EXISTS template_element_texts (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  template_element_id bigint NOT NULL,
  text text NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_tags
--

CREATE TABLE IF NOT EXISTS template_tags (
  id bigserial NOT NULL,
  template_id bigint NOT NULL,
  tag_id bigint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table threads
--

CREATE TABLE IF NOT EXISTS threads (
  id bigserial NOT NULL,
  date_created timestamp NOT NULL,
  date_modified timestamp NOT NULL,
  distribution smallint NOT NULL,
  user_id bigint NOT NULL,
  post_count bigint NOT NULL,
  event_id bigint NOT NULL,
  title varchar(255) NOT NULL,
  org_id bigint NOT NULL,
  sharing_group_id bigint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_threads_user_id ON threads (user_id);
CREATE INDEX idx_threads_event_id ON threads (event_id);
CREATE INDEX idx_threads_org_id ON threads (org_id);
CREATE INDEX idx_threads_sharing_group_id ON threads (sharing_group_id);

-- --------------------------------------------------------

--
-- Table structure for table threat_levels
--

CREATE TABLE IF NOT EXISTS threat_levels (
  id bigserial NOT NULL,
  name varchar(50) NOT NULL,
  description varchar(255) DEFAULT NULL,
  form_description varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table users
--

CREATE TABLE IF NOT EXISTS users (
  id bigserial NOT NULL,
  password varchar(40) NOT NULL,
  org_id bigint NOT NULL,
  server_id bigint NOT NULL DEFAULT 0,
  email varchar(255) NOT NULL,
  autoalert smallint NOT NULL DEFAULT 0,
  authkey varchar(40) DEFAULT NULL,
  invited_by bigint NOT NULL DEFAULT 0,
  gpgkey text,
  certif_public text,
  nids_sid bigint NOT NULL DEFAULT 0,
  termsaccepted smallint NOT NULL DEFAULT 0,
  newsread bigint DEFAULT 0,
  role_id bigint NOT NULL DEFAULT 0,
  change_pw smallint NOT NULL DEFAULT 0,
  contactalert smallint NOT NULL DEFAULT 0,
  disabled BOOLEAN NOT NULL DEFAULT false,
  expiration timestamp DEFAULT NULL,
  current_login bigint DEFAULT 0,
  last_login bigint DEFAULT 0,
  force_logout smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_org_id ON users (org_id);
CREATE INDEX idx_users_server_id ON users (server_id);

-- --------------------------------------------------------

--
-- Table structure for table warninglists
--

CREATE TABLE IF NOT EXISTS warninglists (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  type varchar(255) NOT NULL DEFAULT 'string',
  description text NOT NULL,
  version bigint NOT NULL DEFAULT '1',
  enabled smallint NOT NULL DEFAULT 0,
  warninglist_entry_count bigint DEFAULT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table warninglist_entries
--

CREATE TABLE IF NOT EXISTS warninglist_entries (
  id bigserial NOT NULL,
  value text NOT NULL,
  warninglist_id bigint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table warninglist_types
--

CREATE TABLE IF NOT EXISTS warninglist_types (
  id bigserial NOT NULL,
  type varchar(255) NOT NULL,
  warninglist_id bigint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table whitelist
--

CREATE TABLE IF NOT EXISTS whitelist (
  id bigserial NOT NULL,
  name text NOT NULL,
  PRIMARY KEY (id)
);
