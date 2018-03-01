-- Clear tables that should be empty
TRUNCATE `attributes`;
TRUNCATE `attribute_tags`;
TRUNCATE `cake_sessions`;
TRUNCATE `correlations`;
TRUNCATE `events`;
TRUNCATE `event_blacklists`;
TRUNCATE `event_delegations`;
TRUNCATE `event_tags`;
TRUNCATE `favourite_tags`;
TRUNCATE `jobs`;
TRUNCATE `logs`;
TRUNCATE `objects`;
TRUNCATE `object_references`;
TRUNCATE `object_relationships`;
TRUNCATE `object_templates`;
TRUNCATE `object_template_elements`;
TRUNCATE `org_blacklists`;
TRUNCATE `posts`;
TRUNCATE `servers`;
TRUNCATE `shadow_attributes`;
TRUNCATE `shadow_attribute_correlations`;
TRUNCATE `sharing_groups`;
TRUNCATE `sharing_group_orgs`;
TRUNCATE `sharing_group_servers`;
TRUNCATE `sightings`;
TRUNCATE `tags`;
TRUNCATE `threads`;
TRUNCATE `bruteforces`;
TRUNCATE `news`;
TRUNCATE `template_tags`;
TRUNCATE `whitelist`;

-- Clear tables that can be re-populated
TRUNCATE `taxonomies`;
TRUNCATE `taxonomy_entries`;
TRUNCATE `taxonomy_predicates`;
TRUNCATE `warninglists`;
TRUNCATE `warninglist_entries`;
TRUNCATE `warninglist_types`;
TRUNCATE `galaxies`;
TRUNCATE `galaxy_clusters`;
TRUNCATE `galaxy_elements`;
TRUNCATE `galaxy_reference`;

-- Clear tables that have defaults
TRUNCATE `feeds`;
TRUNCATE `regexp`;
TRUNCATE `roles`;
TRUNCATE `threat_levels`;
TRUNCATE `templates`;
TRUNCATE `template_elements`;
TRUNCATE `template_element_attributes`;
TRUNCATE `template_element_files`;
TRUNCATE `template_element_texts`;

-- Remove entries from tables and reset index
DELETE FROM `users` WHERE id > 3;
ALTER TABLE `users` AUTO_INCREMENT = 4;
DELETE FROM `organisations` WHERE id > 2;
ALTER TABLE `organisations` AUTO_INCREMENT = 3;
