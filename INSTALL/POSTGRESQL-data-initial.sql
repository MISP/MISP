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

--
-- Data for Name: admin_settings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.admin_settings (id, setting, value) FROM stdin;
1	db_version	11
\.


--
-- Data for Name: attribute_tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attribute_tags (id, attribute_id, event_id, tag_id) FROM stdin;
\.


--
-- Data for Name: attributes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.attributes (id, event_id, object_id, object_relation, category, type, value1, value2, to_ids, uuid, "timestamp", distribution, sharing_group_id, comment, deleted, disable_correlation) FROM stdin;
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

COPY public.correlations (id, value, "1_event_id", "1_attribute_id", event_id, attribute_id, org_id, distribution, a_distribution, sharing_group_id, a_sharing_group_id, date, info) FROM stdin;
\.


--
-- Data for Name: event_blacklists; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_blacklists (id, event_uuid, created, event_info, comment, event_orgc) FROM stdin;
\.


--
-- Data for Name: event_delegations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_delegations (id, org_id, requester_org_id, event_id, message, distribution, sharing_group_id) FROM stdin;
\.


--
-- Data for Name: event_locks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_locks (id, event_id, user_id, "timestamp") FROM stdin;
\.


--
-- Data for Name: event_tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.event_tags (id, event_id, tag_id) FROM stdin;
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

COPY public.feeds (id, name, provider, url, rules, enabled, distribution, sharing_group_id, tag_id, "default", source_format, fixed_event, delta_merge, event_id, publish, override_ids, settings, input_source, delete_local_file, lookup_visible, headers, caching_enabled) FROM stdin;
1	CIRCL OSINT Feed	CIRCL	https://www.circl.lu/doc/misp/feed-osint	\N	f	3	0	0	t	misp	f	f	0	f	f	\N	network	f	f	\N	f
2	The Botvrij.eu Data	Botvrij.eu	https://www.botvrij.eu/data/feed-osint	\N	f	3	0	0	t	misp	f	f	0	f	f	\N	network	f	f	\N	f
\.


--
-- Data for Name: fuzzy_correlate_ssdeep; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.fuzzy_correlate_ssdeep (id, chunk, attribute_id) FROM stdin;
\.


--
-- Data for Name: galaxies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.galaxies (id, uuid, name, type, description, version, icon, namespace) FROM stdin;
\.


--
-- Data for Name: galaxy_clusters; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.galaxy_clusters (id, uuid, type, value, tag_name, description, galaxy_id, source, authors, version) FROM stdin;
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

COPY public.objects (id, name, "meta-category", description, template_uuid, template_version, event_id, uuid, "timestamp", distribution, sharing_group_id, comment, deleted) FROM stdin;
\.


--
-- Data for Name: org_blacklists; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.org_blacklists (id, org_uuid, created, org_name, comment) FROM stdin;
1	58d38339-7b24-4386-b4b4-4c0f950d210f	2018-11-27 06:22:00+00	Setec Astrononomy	default example
2	58d38326-eda8-443a-9fa8-4e12950d210f	2018-11-27 06:22:00+00	Acme Finance	default example
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
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_delegate, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_site_admin, perm_regexp_access, perm_tagger, perm_template, perm_sharing_group, perm_tag_editor, perm_sighting, perm_object_template, default_role, memory_limit, max_execution_time, restricted_to_site_admin, perm_publish_zmq, perm_publish_kafka, perm_decaying) FROM stdin;
1	admin	2018-11-27 06:22:00+00	2018-11-27 06:22:00+00	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	t	f			f	t	t	t
2	Org Admin	2018-11-27 06:22:00+00	2018-11-27 06:22:00+00	t	t	t	t	t	f	t	t	f	t	f	f	t	t	t	t	t	f	f			f	t	t	t
3	User	2018-11-27 06:22:00+00	2018-11-27 06:22:00+00	t	t	t	f	f	f	f	f	f	t	f	f	f	f	f	f	t	f	t			f	f	f	t
4	Publisher	2018-11-27 06:22:00+00	2018-11-27 06:22:00+00	t	t	t	t	t	f	f	f	f	t	f	f	f	f	f	f	t	f	f			f	t	t	t
5	Sync user	2018-11-27 06:22:00+00	2018-11-27 06:22:00+00	t	t	t	t	t	t	f	f	f	t	f	f	f	f	t	f	t	f	f			f	t	t	t
6	Read Only	2018-11-27 06:22:00+00	2018-11-27 06:22:00+00	f	f	f	f	f	f	f	f	f	t	f	f	f	f	f	f	f	f	f			f	f	f	f
\.


--
-- Data for Name: servers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.servers (id, name, url, authkey, org_id, push, pull, push_sightings, lastpulledid, lastpushedid, organization, remote_org_id, publish_without_email, unpublish_event, self_signed, pull_rules, push_rules, cert_file, client_cert_file, internal) FROM stdin;
\.


--
-- Data for Name: shadow_attribute_correlations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.shadow_attribute_correlations (id, org_id, value, distribution, a_distribution, sharing_group_id, a_sharing_group_id, attribute_id, "1_shadow_attribute_id", event_id, "1_event_id", info) FROM stdin;
\.


--
-- Data for Name: shadow_attributes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.shadow_attributes (id, old_id, event_id, type, category, value1, to_ids, uuid, value2, org_id, email, event_org_id, comment, event_uuid, deleted, "timestamp", proposal_to_delete, disable_correlation) FROM stdin;
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
-- Data for Name: sightings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sightings (id, attribute_id, event_id, org_id, date_sighting, uuid, source, type) FROM stdin;
\.


--
-- Data for Name: tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.tags (id, name, colour, exportable, org_id, user_id, hide_tag) FROM stdin;
\.


--
-- Data for Name: tasks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.tasks (id, type, timer, scheduled_time, process_id, description, next_execution_time, message) FROM stdin;
\.


--
-- Data for Name: taxonomies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.taxonomies (id, namespace, description, version, enabled) FROM stdin;
\.


--
-- Data for Name: taxonomy_entries; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.taxonomy_entries (id, taxonomy_predicate_id, value, expanded, colour) FROM stdin;
\.


--
-- Data for Name: taxonomy_predicates; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.taxonomy_predicates (id, taxonomy_id, value, expanded, colour) FROM stdin;
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
-- Data for Name: whitelist; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.whitelist (id, name) FROM stdin;
\.


--
-- Name: admin_settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.admin_settings_id_seq', 1, true);


--
-- Name: attribute_tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attribute_tags_id_seq', 1, true);


--
-- Name: attributes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.attributes_id_seq', 1, true);


--
-- Name: correlations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.correlations_id_seq', 1, true);


--
-- Name: event_blacklists_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.event_blacklists_id_seq', 1, true);


--
-- Name: event_delegations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.event_delegations_id_seq', 1, true);


--
-- Name: event_locks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.event_locks_id_seq', 1, true);


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
-- Name: org_blacklists_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.org_blacklists_id_seq', 2, true);


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
-- Name: sightings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sightings_id_seq', 1, true);


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
-- Name: whitelist_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.whitelist_id_seq', 1, true);


--
-- PostgreSQL database dump complete
--

