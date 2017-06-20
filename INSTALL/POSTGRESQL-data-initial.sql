-- --------------------------------------------------------

--
-- Default values for initial installation
--

INSERT INTO admin_settings (id, setting, value) VALUES
(1, 'db_version', '2.4.51');
SELECT SETVAL('admin_settings_id_seq', (SELECT MAX(id) FROM admin_settings));

INSERT INTO feeds (id, provider, name, url, distribution, "default", enabled) VALUES
(1, 'CIRCL', 'CIRCL OSINT Feed', 'https://www.circl.lu/doc/misp/feed-osint', 3, 1, 0),
(2, 'Botvrij.eu', 'The Botvrij.eu Data', 'http://www.botvrij.eu/data/feed-osint', 3, 1, 0);
SELECT SETVAL('feeds_id_seq', (SELECT MAX(id) FROM feeds));

INSERT INTO regexp (id, regexp, replacement, type) VALUES
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
SELECT SETVAL('regexp_id_seq', (SELECT MAX(id) FROM regexp));

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

INSERT INTO roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor, perm_delegate, default_role)
VALUES (1, 'admin', NOW(), NOW(), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0);

INSERT INTO roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor, perm_delegate, default_role)
VALUES ('2', 'Org Admin', NOW(), NOW(), 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0);

INSERT INTO roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor, perm_delegate, default_role)
VALUES ('3', 'User', NOW(), NOW(), 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1);

INSERT INTO roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor, perm_delegate, default_role)
VALUES ('4', 'Publisher', NOW(), NOW(), 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0);

INSERT INTO roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor, perm_delegate, default_role)
VALUES ('5', 'Sync user', NOW(), NOW(), 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0);

INSERT INTO roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor, perm_delegate, default_role)
VALUES ('6', 'Read Only', NOW(), NOW(), 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0);

SELECT SETVAL('roles_id_seq', (SELECT MAX(id) FROM roles));

-- --------------------------------------------------------

--
-- Initial threat levels
--

INSERT INTO threat_levels (id, name, description, form_description)
VALUES
  (1, 'High', '*high* means sophisticated APT malware or 0-day attack', 'Sophisticated APT malware or 0-day attack'),
  (2, 'Medium', '*medium* means APT malware', 'APT malware'),
  (3, 'Low', '*low* means mass-malware', 'Mass-malware'),
  (4, 'Undefined', '*undefined* no risk', 'No risk');
SELECT SETVAL('threat_levels_id_seq', (SELECT MAX(id) FROM threat_levels));

-- --------------------------------------------------------

--
-- Default templates
--

INSERT INTO templates (id, name, description, org, share) VALUES
(1, 'Phishing E-mail', 'Create a MISP event about a Phishing E-mail.', 'MISP', 1),
(2, 'Phishing E-mail with malicious attachment', 'A MISP event based on Spear-phishing containing a malicious attachment. This event can include anything from the description of the e-mail itself, the malicious attachment and its description as well as the results of the analysis done on the malicious f', 'MISP', 1),
(3, 'Malware Report', 'This is a template for a generic malware report. ', 'MISP', 1),
(4, 'Indicator List', 'A simple template for indicator lists.', 'MISP', 1);
SELECT SETVAL('templates_id_seq', (SELECT MAX(id) FROM templates));

INSERT INTO template_elements (id, template_id, position, element_definition) VALUES
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
SELECT SETVAL('template_elements_id_seq', (SELECT MAX(id) FROM template_elements));

INSERT INTO template_element_attributes (id, template_element_id, name, description, to_ids, category, complex, type, mandatory, batch) VALUES
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
SELECT SETVAL('template_element_attributes_id_seq', (SELECT MAX(id) FROM template_element_attributes));

INSERT INTO template_element_files (id, template_element_id, name, description, category, malware, mandatory, batch) VALUES
(1, 14, 'Malicious Attachment', 'The file (or files) that was (were) attached to the e-mail itself.', 'Payload delivery', 1, 0, 1),
(2, 21, 'Payload installation', 'Payload installation detected during the analysis', 'Payload installation', 1, 0, 1),
(3, 30, 'Malware sample', 'The sample that the report is based on', 'Payload delivery', 1, 0, 0),
(4, 40, 'Artifacts dropped (Sample)', 'Upload any files that were dropped during the analysis.', 'Artifacts dropped', 1, 0, 1);
SELECT SETVAL('template_element_files_id_seq', (SELECT MAX(id) FROM template_element_files));

INSERT INTO template_element_texts (id, name, template_element_id, text) VALUES
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
SELECT SETVAL('template_element_texts_id_seq', (SELECT MAX(id) FROM template_element_texts));

INSERT INTO org_blacklists (id, org_uuid, created, org_name, comment) VALUES
(1, '58d38339-7b24-4386-b4b4-4c0f950d210f', NOW(), 'Setec Astrononomy', 'default example'),
(2, '58d38326-eda8-443a-9fa8-4e12950d210f', NOW(), 'Acme Finance', 'default example');
SELECT SETVAL('org_blacklists_id_seq', (SELECT MAX(id) FROM org_blacklists));
