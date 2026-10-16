<?php

App::uses('AbstractGrammar', 'Migration/Grammar');
App::uses('BaselineGenerator', 'Migration');
App::uses('Collation', 'Migration');
App::uses('SchemaInspector', 'Migration');

/**
 * Derives the 3.0 schema target of every table from a reference database:
 * 64-bit ids and epochs, utf8mb4 with the collation classes, ascii for uuids
 * and hex hashes, the high-performance index pack in the baseline, redundant
 * indexes retired, InnoDB DYNAMIC everywhere.
 *
 * The reference is a fresh install brought to the newest migration, read
 * through BaselineGenerator::readSchema(). Each table's target is copied into
 * the migration that converges that table, as a frozen constant: a migration's
 * meaning must not change when this class does, so nothing ever reads a
 * target from here at run time.
 *
 * A target is:
 *   'options' => engine, row_format, collate (a Collation token)
 *   'columns' => name => DSL spec, in the reference's order; every string
 *                column names its collation, integers carry no display width
 *   'indexes' => name => array('column' => list, 'unique', 'length' (TEXT
 *                prefixes only), 'fulltext', 'pgsql', 'mysql'), the complete
 *                set; 'pgsql' => array('name', 'sql'[, 'extension']) replaces
 *                the index on PostgreSQL, 'mysql' => false marks one that
 *                exists there only
 *   'retired' => index names to drop where an instance has them; any other
 *                index an instance has and the target lacks is the admin's
 *                and is kept
 */
class SchemaTargetGenerator
{
    /**
     * tasks and correlations are dropped rather than converged; the log
     * tables are not converged.
     */
    const EXCLUDED_TABLES = array('tasks', 'correlations', 'logs', 'audit_logs');

    /** References to another table's id that are not named *_id. */
    const HIDDEN_ID_COLUMNS = array(
        'organisations' => array('created_by'),
        'servers' => array('lastpulledid', 'lastpushedid'),
        'users' => array('invited_by'),
    );

    /** Epoch seconds held in a 32-bit integer. */
    const EPOCH_COLUMNS = array(
        'attachment_scans' => array('timestamp'),
        'attributes' => array('timestamp'),
        'auth_keys' => array('created', 'expiration'),
        'cake_sessions' => array('expires'),
        'correlation_rules' => array('created', 'timestamp'),
        'cryptographic_keys' => array('timestamp'),
        'dashboards' => array('timestamp'),
        'event_graph' => array('timestamp'),
        'event_locks' => array('timestamp'),
        'event_reports' => array('timestamp'),
        'events' => array('timestamp', 'publish_timestamp', 'sighting_timestamp', 'first_publication'),
        'inbox' => array('timestamp'),
        'news' => array('date_created'),
        'notification_logs' => array('timestamp'),
        'object_references' => array('timestamp'),
        'objects' => array('timestamp'),
        'rest_client_histories' => array('timestamp'),
        'scheduled_tasks' => array('next_execution_time', 'last_run_at'),
        'shadow_attributes' => array('timestamp'),
        'sharing_group_blueprints' => array('timestamp'),
        'sightingdbs' => array('timestamp'),
        'user_settings' => array('timestamp'),
        'users' => array('current_login', 'last_login', 'last_api_access', 'newsread'),
        'value_enrichment_runs' => array('last_run'),
        'workflow_blueprints' => array('timestamp'),
        'workflows' => array('timestamp'),
    );

    /** JSON blobs that can outgrow 64 KB. */
    const MEDIUMTEXT_COLUMNS = array(
        'dashboards' => array('value'),
        'feeds' => array('rules'),
        'servers' => array('push_rules', 'pull_rules'),
        'user_settings' => array('value'),
    );

    /**
     * Merged into the spec after the other column rules.
     *
     * correlation_rules.created defaulted to UNIX_TIMESTAMP(), which MySQL 8.4
     * refuses unparenthesised; CorrelationRule::beforeValidate() sets it on
     * every new rule. created_at is the schema's only TIMESTAMP column, which
     * ends in 2038 on MySQL.
     */
    const COLUMN_OVERRIDES = array(
        'correlation_rules' => array('created' => array('default' => '0')),
        'user_login_profiles' => array('created_at' => array('type' => 'datetime')),
    );

    /**
     * Uuids and hex hashes: ascii with a byte comparison, so that any two of
     * them can be joined through an index.
     */
    const ASCII_COLUMNS = array(
        'analyst_data_blocklists' => array('analyst_data_uuid'),
        'analyst_graphs' => array('uuid', 'object_uuid', 'org_uuid', 'orgc_uuid', 'forked_from_uuid'),
        'analyst_profile_selections' => array('uuid'),
        'analyst_profiles' => array('uuid'),
        'attributes' => array('uuid'),
        'auth_keys' => array('uuid', 'authkey', 'authkey_start', 'authkey_end'),
        'collection_elements' => array('uuid', 'element_uuid', 'element_sha256'),
        'collections' => array('uuid'),
        'correlation_rules' => array('uuid'),
        'cryptographic_keys' => array('uuid', 'fingerprint'),
        'dashboards' => array('uuid'),
        'decaying_models' => array('uuid'),
        'event_blocklists' => array('event_uuid'),
        'event_reports' => array('uuid'),
        'event_template_object_dependencies' => array('object_template_uuid'),
        'event_templates' => array('uuid'),
        'events' => array('uuid', 'extends_uuid'),
        'galaxies' => array('uuid'),
        'galaxy_cluster_blocklists' => array('cluster_uuid'),
        'galaxy_cluster_relations' => array('galaxy_cluster_uuid', 'referenced_galaxy_cluster_uuid'),
        'galaxy_clusters' => array('uuid', 'collection_uuid', 'extends_uuid'),
        'inbox' => array('uuid', 'user_agent_sha256'),
        'notes' => array('uuid', 'object_uuid', 'object_sha256', 'org_uuid', 'orgc_uuid'),
        'object_references' => array('uuid', 'source_uuid', 'referenced_uuid'),
        'object_templates' => array('uuid'),
        'objects' => array('uuid', 'template_uuid'),
        'opinions' => array('uuid', 'object_uuid', 'object_sha256', 'org_uuid', 'orgc_uuid'),
        'org_blocklists' => array('org_uuid'),
        'organisations' => array('uuid'),
        'relationships' => array(
            'uuid', 'object_uuid', 'object_sha256', 'related_object_uuid', 'related_object_sha256',
            'org_uuid', 'orgc_uuid',
        ),
        'shadow_attributes' => array('uuid', 'event_uuid'),
        'sharing_group_blueprints' => array('uuid'),
        'sharing_groups' => array('uuid', 'organisation_uuid'),
        'sighting_blocklists' => array('org_uuid'),
        'sightings' => array('uuid'),
        'tag_collections' => array('uuid'),
        'taxii_servers' => array('uuid'),
        'user_login_profiles' => array('hash'),
        'users' => array('authkey'),
        'value_enrichment_runs' => array('value_hash'),
        'workflow_blueprints' => array('uuid'),
        'workflows' => array('uuid'),
    );

    /** Names that look like a uuid or hash column; one not listed above is reported. */
    const ASCII_NAME_PATTERN = '/^(uuid|.+_uuid|.+_sha256|hash|authkey.*|fingerprint)$/';

    /** Type names compared case-insensitively, kept in the collation they have. */
    const KEPT_COLLATIONS = array(
        'analyst_graphs' => array('object_type' => 'ascii_general_ci'),
        'collection_elements' => array('element_type' => 'ascii_general_ci'),
        'collections' => array('type' => 'ascii_general_ci'),
        'notes' => array('object_type' => 'ascii_general_ci'),
        'opinions' => array('object_type' => 'ascii_general_ci'),
        'relationships' => array(
            'object_type' => 'ascii_general_ci',
            'related_object_type' => 'ascii_general_ci',
        ),
    );

    /** Integer names that look like epoch seconds; one not listed above is reported. */
    const EPOCH_NAME_PATTERN = '/(^|_)(timestamp|created|modified|expires|expiration|newsread)$|^date_|_at$|_time$|_login$|_access$/';

    /**
     * Was `Admin runDBScript highPerformance`, now part of the schema. A
     * varchar column is indexed whole; TEXT keeps its prefix.
     */
    const INDEX_ADDITIONS = array(
        'attribute_tags' => array(
            'idx_attr_tags_event_tag' => array('column' => array('event_id', 'tag_id')),
            'idx_attr_tags_attr_tag' => array('column' => array('attribute_id', 'tag_id')),
        ),
        'attributes' => array(
            'idx_attr_acl_type' => array('column' => array('event_id', 'distribution', 'sharing_group_id', 'deleted', 'type')),
            'idx_attr_type_event' => array('column' => array('type', 'event_id')),
            'idx_attr_obj_dist' => array('column' => array('object_id', 'distribution')),
            'idx_attr_objrel_acl' => array(
                'column' => array('object_relation', 'event_id', 'distribution', 'sharing_group_id', 'deleted'),
            ),
            'idx_attr_search_core' => array(
                'column' => array('type', 'to_ids', 'deleted', 'distribution', 'sharing_group_id', 'event_id'),
            ),
            'idx_attr_acl_primary' => array('column' => array('deleted', 'distribution', 'sharing_group_id', 'event_id')),
            'idx_attr_ts_acl' => array(
                'column' => array('timestamp', 'deleted', 'distribution', 'sharing_group_id', 'event_id'),
            ),
            'idx_attr_deleted_ts' => array('column' => array('deleted', 'timestamp', 'id')),
            // Cursor-paged single-type exports: type = X AND id > last ORDER BY id.
            'idx_attr_type_id' => array('column' => array('type', 'id')),
        ),
        'default_correlations' => array(
            'idx_corr_acl_src' => array('column' => array(
                'object_id', 'org_id', 'distribution', 'sharing_group_id', 'event_distribution', 'event_sharing_group_id',
            )),
            'idx_corr_acl_dst' => array('column' => array(
                '1_object_id', '1_org_id', '1_distribution', '1_sharing_group_id', '1_event_distribution',
                '1_event_sharing_group_id',
            )),
            'idx_corr_acl_src_obj' => array('column' => array(
                'object_id', 'org_id', 'distribution', 'sharing_group_id', 'object_distribution',
                'object_sharing_group_id', 'event_distribution', 'event_sharing_group_id',
            )),
            'idx_corr_acl_dst_obj' => array('column' => array(
                '1_object_id', '1_org_id', '1_distribution', '1_sharing_group_id', '1_object_distribution',
                '1_object_sharing_group_id', '1_event_distribution', '1_event_sharing_group_id',
            )),
            'idx_corr_evt_1evt' => array('column' => array('event_id', '1_event_id')),
        ),
        'event_tags' => array(
            'idx_event_tags_event_tag' => array('column' => array('event_id', 'tag_id')),
        ),
        'events' => array(
            'idx_evt_acl' => array('column' => array('distribution', 'sharing_group_id')),
            'idx_evt_ts_pub' => array('column' => array('timestamp', 'published')),
            'idx_evt_id_acl' => array('column' => array('id', 'org_id', 'distribution', 'sharing_group_id')),
            'idx_evt_acl_flex' => array('column' => array('org_id', 'distribution', 'sharing_group_id', 'id')),
        ),
        'no_acl_correlations' => array(
            'idx_nac_attr_evt' => array('column' => array('attribute_id', 'event_id')),
            'idx_nac_1attr_1evt' => array('column' => array('1_attribute_id', '1_event_id')),
            'idx_nac_val_attr' => array('column' => array('value_id', 'attribute_id')),
            'idx_nac_val_1attr' => array('column' => array('value_id', '1_attribute_id')),
            'idx_nac_evt_1evt' => array('column' => array('event_id', '1_event_id')),
        ),
        'objects' => array(
            'idx_obj_acl' => array('column' => array('event_id', 'distribution', 'sharing_group_id', 'deleted')),
            'idx_obj_id_acl' => array('column' => array('id', 'event_id', 'distribution')),
            'idx_obj_meta' => array('column' => array('meta-category', 'timestamp')),
        ),
        'warninglist_entries' => array(
            'idx_warn_values' => array('column' => array('value'), 'length' => array('value' => 64)),
        ),
    );

    /**
     * Indexes the target drops: the pack's own drops, and indexes another one
     * starts with. Some exist only where the pack ran. idx_attr_type_ts is the
     * pack's too, and its own comment says it hurt more than it helped.
     */
    const RETIRED_INDEXES = array(
        'attribute_tags' => array('attribute_id', 'event_id'),
        'attributes' => array(
            'deleted', 'event_id', 'idx_attr_evt_dist', 'idx_attr_type_ts', 'object_id', 'object_relation',
            'timestamp', 'type',
        ),
        'collection_elements' => array('element_uuid'),
        'default_correlations' => array('1_object_id', 'attribute_id', 'event_id', 'object_id'),
        'event_tags' => array('event_id'),
        'events' => array('org_id', 'sharing_group_id'),
        'no_acl_correlations' => array('1_attribute_id', 'attribute_id', 'event_id', 'value_id'),
        'objects' => array('distribution', 'event_id', 'meta-category', 'sharing_group_id'),
        'user_settings' => array('user_id'),
    );

    /** InnoDB's key limit under ROW_FORMAT=DYNAMIC. */
    const MYSQL_KEY_LIMIT = 3072;

    /** The largest btree entry PostgreSQL accepts (version 4 btrees, PostgreSQL 12 and later). */
    const PGSQL_BTREE_LIMIT = 2704;

    /** Lines the exporter keeps an array on before it breaks it up. */
    const EXPORT_WIDTH = 120;

    const STRING_TYPES = array('string', 'text', 'mediumtext', 'longtext');

    const INTEGER_TYPES = array('integer', 'biginteger', 'smallinteger', 'tinyinteger');

    /** @var array table => list of what was changed and why */
    private $notes = array();

    /** @var array Things a reviewer should look at; none of them stops the run. */
    private $warnings = array();

    /** @var array table.index => array('mysql' => bytes, 'pgsql' => bytes|null|false) */
    private $keyLengths = array();

    /** @var array */
    private $errors = array();

    /** @var array rule => list, the constants above unless a test replaced one */
    private $rules;

    /**
     * @param array $rules Replaces rule lists by key: excluded, hiddenIds,
     *   epoch, mediumtext, overrides, ascii, kept, additions, retired,
     *   pgsqlReplaced, pgsqlOnly.
     * @throws InvalidArgumentException On an unknown key.
     */
    public function __construct(array $rules = array())
    {
        $defaults = array(
            'excluded' => self::EXCLUDED_TABLES,
            'hiddenIds' => self::HIDDEN_ID_COLUMNS,
            'epoch' => self::EPOCH_COLUMNS,
            'mediumtext' => self::MEDIUMTEXT_COLUMNS,
            'overrides' => self::COLUMN_OVERRIDES,
            'ascii' => self::ASCII_COLUMNS,
            'kept' => self::KEPT_COLLATIONS,
            'additions' => self::INDEX_ADDITIONS,
            'retired' => self::RETIRED_INDEXES,
            'pgsqlReplaced' => BaselineGenerator::PGSQL_REPLACED_INDEXES,
            'pgsqlOnly' => BaselineGenerator::PGSQL_ONLY_INDEXES,
        );
        $unknown = array_diff_key($rules, $defaults);
        if (!empty($unknown)) {
            throw new InvalidArgumentException('Unknown rule: ' . implode(', ', array_keys($unknown)));
        }
        $this->rules = array_merge($defaults, $rules);
    }

    /**
     * @param array $schema BaselineGenerator::readSchema() of the reference.
     * @return array table => target, by table name.
     * @throws RuntimeException Listing every inconsistency between the rules and the reference.
     */
    public function generate(array $schema)
    {
        $this->notes = $this->warnings = $this->keyLengths = $this->errors = array();
        $this->checkListedTables($schema);

        $targets = array();
        foreach ($schema as $table => $definition) {
            if (in_array($table, $this->rules['excluded'], true)) {
                continue;
            }
            $targets[$table] = $this->target($table, $definition);
        }
        // The reference lists tables in its server's collation order.
        ksort($targets, SORT_STRING);

        if (!empty($this->errors)) {
            throw new RuntimeException("The rules do not fit the reference:\n" . implode("\n", $this->errors));
        }
        return $targets;
    }

    /**
     * @return array table => list of strings
     */
    public function notes()
    {
        return $this->notes;
    }

    /**
     * @return array
     */
    public function warnings()
    {
        return $this->warnings;
    }

    /**
     * @return array table.index => array('mysql' => int, 'pgsql' => int|null|false):
     *   null when PostgreSQL bounds the entry by nothing, false when it is not a btree there.
     */
    public function keyLengths()
    {
        return $this->keyLengths;
    }

    /**
     * What generate() did, for review: the warnings, the widest keys, the
     * ascii columns, and every change per table.
     *
     * @param array $targets From generate().
     * @param string $source The reference, as it should be named.
     * @param int $widest How many keys to list.
     * @return string
     */
    public function report(array $targets, $source, $widest = 15)
    {
        $out = array(
            '# Schema targets',
            '',
            sprintf('%d tables from %s; not converged: %s.', count($targets), $source, implode(', ', $this->rules['excluded'])),
            '',
            sprintf('## Warnings (%d)', count($this->warnings)),
            '',
        );
        foreach ($this->warnings as $warning) {
            $out[] = '- ' . $warning;
        }

        $out[] = '';
        $out[] = sprintf('## Widest keys, in bytes (limits: MySQL %d, PostgreSQL btree %d)', self::MYSQL_KEY_LIMIT, self::PGSQL_BTREE_LIMIT);
        $out[] = '';
        $lengths = $this->keyLengths;
        uasort($lengths, function ($a, $b) {
            return $b['mysql'] - $a['mysql'];
        });
        foreach (array_slice($lengths, 0, $widest, true) as $index => $bytes) {
            $pgsql = $bytes['pgsql'] === false ? 'not a btree' : ($bytes['pgsql'] === null ? 'unbounded' : $bytes['pgsql']);
            $out[] = sprintf('- %s: MySQL %d, PostgreSQL %s', $index, $bytes['mysql'], $pgsql);
        }

        $ascii = array();
        foreach ($targets as $table => $target) {
            foreach ($target['columns'] as $column => $spec) {
                if (isset($spec['collate']) && $spec['collate'] === Collation::ASCII) {
                    $ascii[] = $table . '.' . $column;
                }
            }
        }
        $out[] = '';
        $out[] = sprintf('## ascii_bin columns (%d)', count($ascii));
        $out[] = '';
        $out[] = implode(', ', $ascii);

        $out[] = '';
        $out[] = '## Changes per table';
        foreach ($targets as $table => $target) {
            if (empty($this->notes[$table])) {
                continue;
            }
            $out[] = '';
            $out[] = '### ' . $table;
            $out[] = '';
            foreach ($this->notes[$table] as $note) {
                $out[] = '- ' . $note;
            }
        }
        return implode("\n", $out) . "\n";
    }

    // ----------------------------------------------------------------- tables

    /**
     * @param string $table
     * @param array $definition One table of readSchema().
     * @return array
     */
    private function target($table, array $definition)
    {
        $tableCollation = isset($definition['options']['collate']) ? $definition['options']['collate'] : null;
        $expressionDefaults = $definition['expressionDefaults'];

        $columns = array();
        foreach ($definition['columns'] as $column => $spec) {
            $columns[$column] = $this->column($table, $column, $spec, $tableCollation, $expressionDefaults);
        }
        foreach ($expressionDefaults as $column => $expression) {
            $this->errors[] = sprintf('%s.%s: expression default %s has no rule.', $table, $column, $expression);
        }

        $retired = isset($this->rules['retired'][$table]) ? $this->rules['retired'][$table] : array();
        sort($retired);
        $indexes = $this->indexes($table, $definition['indexes'], $columns, $retired);

        $target = array(
            'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
            'columns' => $columns,
            'indexes' => $indexes,
            'retired' => $retired,
        );
        $this->checkKeyLengths($table, $target);
        $this->checkRedundancy($table, $target);
        return $target;
    }

    /**
     * @param array $schema
     * @return void
     */
    private function checkListedTables(array $schema)
    {
        $lists = array(
            'id' => $this->rules['hiddenIds'],
            'epoch' => $this->rules['epoch'],
            'mediumtext' => $this->rules['mediumtext'],
            'ascii' => $this->rules['ascii'],
        );
        foreach ($lists as $rule => $list) {
            foreach ($list as $table => $columns) {
                foreach ($columns as $column) {
                    if (!isset($schema[$table]['columns'][$column])) {
                        $this->errors[] = sprintf('%s.%s (%s rule) is not in the reference.', $table, $column, $rule);
                    }
                }
            }
        }
        $keyed = array(
            'override' => $this->rules['overrides'],
            'kept collation' => $this->rules['kept'],
        );
        foreach ($keyed as $rule => $list) {
            foreach ($list as $table => $columns) {
                foreach (array_keys($columns) as $column) {
                    if (!isset($schema[$table]['columns'][$column])) {
                        $this->errors[] = sprintf('%s.%s (%s rule) is not in the reference.', $table, $column, $rule);
                    }
                }
            }
        }
        $indexLists = array($this->rules['additions'], $this->rules['retired']);
        foreach ($indexLists as $list) {
            foreach (array_keys($list) as $table) {
                if (!isset($schema[$table])) {
                    $this->errors[] = sprintf('Index rules name the table %s, which is not in the reference.', $table);
                }
            }
        }
    }

    /**
     * @param string $rule
     * @param string $table
     * @param string $column
     * @return bool
     */
    private function listed($rule, $table, $column)
    {
        return isset($this->rules[$rule][$table]) && in_array($column, $this->rules[$rule][$table], true);
    }

    // ---------------------------------------------------------------- columns

    /**
     * @param string $table
     * @param string $column
     * @param array $spec From readSchema().
     * @param string|null $tableCollation
     * @param array $expressionDefaults Consumed when an override sets the default.
     * @return array
     */
    private function column($table, $column, array $spec, $tableCollation, array &$expressionDefaults)
    {
        $before = self::describe($spec, $tableCollation);
        $type = $spec['type'];
        $reason = array();

        if (in_array($type, self::INTEGER_TYPES, true) || $type === 'boolean') {
            unset($spec['length']);
        }

        $hidden = $this->listed('hiddenIds', $table, $column);
        $epoch = $this->listed('epoch', $table, $column);
        if (in_array($type, self::INTEGER_TYPES, true)
            && ($column === 'id' || substr($column, -3) === '_id' || $hidden)
        ) {
            $spec['type'] = 'biginteger';
            unset($spec['unsigned']);
            $reason[] = 'id';
        } elseif ($epoch) {
            if (!in_array($type, self::INTEGER_TYPES, true)) {
                $this->errors[] = sprintf('%s.%s (epoch rule) is %s, not an integer.', $table, $column, $type);
            }
            $spec['type'] = 'biginteger';
            unset($spec['unsigned']);
            $reason[] = 'epoch';
        } elseif ($type === 'integer' && preg_match(self::EPOCH_NAME_PATTERN, $column)) {
            $this->warnings[] = sprintf('%s.%s is a 32-bit integer named like an epoch, and is not in the epoch list.', $table, $column);
        }

        if ($this->listed('mediumtext', $table, $column)) {
            if ($type !== 'text' && $type !== 'mediumtext') {
                $this->errors[] = sprintf('%s.%s (mediumtext rule) is %s, not text.', $table, $column, $type);
            }
            $spec['type'] = 'mediumtext';
            $reason[] = 'JSON blob';
        }

        if (isset($this->rules['overrides'][$table][$column])) {
            $override = $this->rules['overrides'][$table][$column];
            $spec = array_merge($spec, $override);
            if (array_key_exists('default', $override)) {
                unset($expressionDefaults[$column]);
            }
            $reason[] = 'override';
        }

        if (in_array($spec['type'], self::STRING_TYPES, true)) {
            list($collation, $why) = $this->collation($table, $column, $spec, $tableCollation);
            unset($spec['charset'], $spec['collate']);
            $spec['collate'] = $collation;
            if (!Collation::isToken($collation)) {
                $spec['charset'] = SchemaInspector::charsetOfCollation($collation);
            }
            $reason[] = $why;
        }

        $spec = self::ordered($spec);
        $after = self::describe($spec, null);
        if ($after !== $before) {
            $this->notes[$table][] = sprintf('%s: %s -> %s (%s)', $column, $before, $after, implode(', ', array_unique($reason)));
        }
        return $spec;
    }

    /**
     * @param string $table
     * @param string $column
     * @param array $spec
     * @param string|null $tableCollation
     * @return array array(collation or token, why)
     */
    private function collation($table, $column, array $spec, $tableCollation)
    {
        if ($this->listed('ascii', $table, $column)) {
            return array(Collation::ASCII, 'uuid/hash');
        }
        if (isset($this->rules['kept'][$table][$column])) {
            return array($this->rules['kept'][$table][$column], 'kept');
        }
        if (preg_match(self::ASCII_NAME_PATTERN, $column)) {
            $this->warnings[] = sprintf('%s.%s is named like a uuid or hash, and is not in the ascii list.', $table, $column);
        }
        $current = isset($spec['collate']) ? $spec['collate'] : $tableCollation;
        if ($current === null) {
            $this->errors[] = sprintf('%s.%s has no collation and neither has its table.', $table, $column);
            return array(Collation::CI, 'class');
        }
        if ($current === Collation::ASCII) {
            $this->warnings[] = sprintf('%s.%s is already ascii_bin, and is not in the ascii list; kept.', $table, $column);
            return array(Collation::ASCII, 'class');
        }
        if (Collation::isToken($current)) {
            return array($current, 'class');
        }
        if (substr($current, -4) === '_bin') {
            return array(Collation::BIN, 'class');
        }
        if (substr($current, -3) === '_ci') {
            return array(Collation::CI, 'class');
        }
        $this->errors[] = sprintf('%s.%s: no class for the collation %s.', $table, $column, $current);
        return array(Collation::CI, 'class');
    }

    /**
     * A column spec's keys in one order, so that two targets diff cleanly.
     *
     * @param array $spec
     * @return array
     */
    private static function ordered(array $spec)
    {
        $order = array('type', 'length', 'unsigned', 'null', 'default', 'collate', 'charset', 'key', 'comment');
        $out = array();
        foreach ($order as $key) {
            if (array_key_exists($key, $spec)) {
                $out[$key] = $spec[$key];
            }
        }
        return $out + $spec;
    }

    /**
     * @param array $spec
     * @param string|null $tableCollation Shown when the column has none of its own.
     * @return string
     */
    private static function describe(array $spec, $tableCollation)
    {
        $out = $spec['type'];
        $width = in_array($spec['type'], self::INTEGER_TYPES, true) || $spec['type'] === 'boolean';
        if (isset($spec['length']) && !$width) {
            $out .= '(' . $spec['length'] . ')';
        }
        if (!empty($spec['unsigned'])) {
            $out .= ' unsigned';
        }
        $out .= empty($spec['null']) ? ' NOT NULL' : ' NULL';
        if (array_key_exists('default', $spec)) {
            $out .= ' DEFAULT ' . var_export($spec['default'], true);
        }
        if (in_array($spec['type'], self::STRING_TYPES, true)) {
            $collation = isset($spec['collate']) ? $spec['collate'] : $tableCollation;
            if ($collation !== null) {
                $out .= ' ' . $collation;
            }
        }
        return $out;
    }

    // ---------------------------------------------------------------- indexes

    /**
     * @param string $table
     * @param array $reference name => readSchema() declaration
     * @param array $columns The target's columns.
     * @param array $retired
     * @return array
     */
    private function indexes($table, array $reference, array $columns, array $retired)
    {
        $indexes = array();
        foreach ($reference as $name => $declaration) {
            $index = array('column' => $declaration['column']);
            if (!empty($declaration['unique'])) {
                $index['unique'] = true;
            }
            if (!empty($declaration['fulltext'])) {
                $index['fulltext'] = true;
            }
            foreach (isset($declaration['length']) ? $declaration['length'] : array() as $column => $length) {
                if (isset($columns[$column]) && $columns[$column]['type'] === 'string') {
                    $this->notes[$table][] = sprintf('index %s: prefix %s(%d) dropped, the varchar is indexed whole', $name, $column, $length);
                    continue;
                }
                $index['length'][$column] = $length;
            }
            $indexes[$name] = $index;
        }

        $additions = isset($this->rules['additions'][$table]) ? $this->rules['additions'][$table] : array();
        $retiredHere = array();
        foreach ($retired as $name) {
            if (isset($indexes[$name])) {
                $retiredHere[$name] = $indexes[$name];
                unset($indexes[$name]);
            }
        }
        foreach ($additions as $name => $index) {
            foreach ($index['column'] as $column) {
                if (!isset($columns[$column])) {
                    $this->errors[] = sprintf('%s: index %s covers %s, which is not a column.', $table, $name, $column);
                }
            }
            if (isset($indexes[$name])) {
                if ($indexes[$name] != $index) {
                    $this->errors[] = sprintf('%s: index %s is in the reference with another definition.', $table, $name);
                }
                continue;
            }
            $indexes[$name] = $index;
            $this->notes[$table][] = sprintf('index %s%s added', $name, self::indexColumns($index));
        }

        foreach ($retired as $name) {
            if (!isset($retiredHere[$name])) {
                $this->notes[$table][] = sprintf('index %s retired; not in the reference, dropped where an instance has it', $name);
                continue;
            }
            $cover = self::coveringIndex($retiredHere[$name], $indexes);
            $this->notes[$table][] = sprintf(
                'index %s%s retired; %s',
                $name,
                self::indexColumns($retiredHere[$name]),
                $cover === null ? 'no target index starts with its columns' : 'covered by ' . $cover
            );
        }

        $replaced = isset($this->rules['pgsqlReplaced'][$table]) ? $this->rules['pgsqlReplaced'][$table] : array();
        foreach ($replaced as $name => $replacement) {
            if (!isset($indexes[$name])) {
                $this->errors[] = sprintf('%s: PostgreSQL replaces the index %s, which the target does not have.', $table, $name);
                continue;
            }
            $indexes[$name]['pgsql'] = array_intersect_key($replacement, array_flip(array('name', 'sql', 'extension')));
        }
        $only = isset($this->rules['pgsqlOnly'][$table]) ? $this->rules['pgsqlOnly'][$table] : array();
        foreach ($only as $name => $sql) {
            $indexes[$name] = array('mysql' => false, 'pgsql' => array('sql' => $sql));
        }

        ksort($indexes);
        return $indexes;
    }

    /**
     * The first other index that starts with every column of $index, in the
     * same order, with prefixes no shorter: it serves every lookup, range and
     * sort $index serves.
     *
     * @param array $index
     * @param array $indexes name => index
     * @param string|null $self The name of $index, to skip it.
     * @return string|null
     */
    public static function coveringIndex(array $index, array $indexes, $self = null)
    {
        if (!empty($index['unique']) || !empty($index['fulltext']) || !isset($index['column'])) {
            return null;
        }
        $width = count($index['column']);
        foreach ($indexes as $name => $other) {
            if ($name === $self || !isset($other['column']) || !empty($other['fulltext'])
                || (isset($other['mysql']) && $other['mysql'] === false)
            ) {
                continue;
            }
            if (count($other['column']) < $width || array_slice($other['column'], 0, $width) !== $index['column']) {
                continue;
            }
            $covers = true;
            foreach ($index['column'] as $column) {
                $mine = isset($index['length'][$column]) ? $index['length'][$column] : null;
                $theirs = isset($other['length'][$column]) ? $other['length'][$column] : null;
                if ($theirs !== null && ($mine === null || $theirs < $mine)) {
                    $covers = false;
                }
            }
            // Of two identical non-unique indexes, only the later name is reported.
            $twin = count($other['column']) === $width && empty($other['unique']);
            if ($covers && !($twin && $self !== null && strcmp($self, $name) < 0)) {
                return $name;
            }
        }
        return null;
    }

    /**
     * @param string $table
     * @param array $target
     * @return void
     */
    private function checkRedundancy($table, array $target)
    {
        foreach ($target['indexes'] as $name => $index) {
            $cover = self::coveringIndex($index, $target['indexes'], $name);
            if ($cover !== null) {
                $this->warnings[] = sprintf('%s: index %s%s is covered by %s%s.', $table, $name, self::indexColumns($index), $cover, self::indexColumns($target['indexes'][$cover]));
            }
        }
    }

    /**
     * @param array $index
     * @return string
     */
    private static function indexColumns(array $index)
    {
        if (!isset($index['column'])) {
            return '';
        }
        $parts = array();
        foreach ($index['column'] as $column) {
            $parts[] = $column . (isset($index['length'][$column]) ? '(' . $index['length'][$column] . ')' : '');
        }
        return ' (' . implode(', ', $parts) . ')';
    }

    // ------------------------------------------------------------ key lengths

    /**
     * @param string $table
     * @param array $target
     * @return void
     */
    private function checkKeyLengths($table, array $target)
    {
        $columns = $target['columns'];
        foreach ($target['indexes'] as $name => $index) {
            if (!isset($index['column']) || !empty($index['fulltext'])
                || array_diff($index['column'], array_keys($columns)) !== array()
            ) {
                continue;
            }
            $mysql = self::keyBytes($columns, $index, AbstractGrammar::FLAVOUR_MYSQL);
            $pgsql = isset($index['pgsql']) || BaselineGenerator::needsHashRewrite($index, $columns)
                ? false
                : self::keyBytes($columns, $index, AbstractGrammar::FLAVOUR_PGSQL);
            $this->keyLengths[$table . '.' . $name] = array('mysql' => $mysql, 'pgsql' => $pgsql);
            if ($mysql > self::MYSQL_KEY_LIMIT) {
                $this->errors[] = sprintf('%s: index %s is %d bytes, over the %d-byte key limit.', $table, $name, $mysql, self::MYSQL_KEY_LIMIT);
            }
            if ($pgsql === null) {
                $this->warnings[] = sprintf(
                    '%s: index %s%s is a full-column btree on PostgreSQL over unbounded text; a value over %d bytes cannot be stored.',
                    $table,
                    $name,
                    self::indexColumns($index),
                    self::PGSQL_BTREE_LIMIT
                );
            } elseif ($pgsql !== false && $pgsql > self::PGSQL_BTREE_LIMIT) {
                $this->errors[] = sprintf('%s: index %s can reach %d bytes on PostgreSQL, over its %d-byte btree entry limit.', $table, $name, $pgsql, self::PGSQL_BTREE_LIMIT);
            }
        }
    }

    /**
     * The most bytes one entry of the index can take: what the MySQL key
     * limit and PostgreSQL's btree entry limit are measured against.
     *
     * @param array $columns name => target spec
     * @param array $index
     * @param string $flavour
     * @return int|null null when nothing bounds it (a whole text column on PostgreSQL).
     */
    public static function keyBytes(array $columns, array $index, $flavour)
    {
        $fixed = array(
            'boolean' => 1, 'tinyinteger' => 1, 'smallinteger' => 2, 'integer' => 4, 'biginteger' => 8,
            'float' => 8, 'decimal' => 16, 'date' => 4, 'time' => 8, 'datetime' => 8, 'timestamp' => 8,
        );
        $total = 0;
        foreach ($index['column'] as $column) {
            $spec = $columns[$column];
            $type = $spec['type'];
            $prefix = isset($index['length'][$column]) ? (int)$index['length'][$column] : null;
            if (isset($fixed[$type])) {
                $total += $fixed[$type];
                continue;
            }
            $perChar = $flavour === AbstractGrammar::FLAVOUR_MYSQL && self::isSingleByte($spec) ? 1 : 4;
            if ($type === 'string') {
                $total += (int)$spec['length'] * $perChar;
            } elseif ($type === 'varbinary') {
                $total += (int)$spec['length'];
            } elseif ($flavour === AbstractGrammar::FLAVOUR_MYSQL && $prefix !== null) {
                $total += $prefix * (in_array($type, self::STRING_TYPES, true) ? $perChar : 1);
            } else {
                return null;
            }
        }
        return $total;
    }

    /**
     * @param array $spec
     * @return bool
     */
    private static function isSingleByte(array $spec)
    {
        if (!isset($spec['collate'])) {
            return false;
        }
        if (Collation::isToken($spec['collate'])) {
            return Collation::charset($spec['collate']) === 'ascii';
        }
        return strpos($spec['collate'], 'ascii_') === 0 || strpos($spec['collate'], 'latin1_') === 0;
    }

    // --------------------------------------------------------------- export

    /**
     * Every target as a PHP file that returns them, for review and diffing.
     *
     * @param array $targets table => target
     * @return string
     */
    public static function exportAll(array $targets)
    {
        $out = "<?php\n\nreturn array(\n";
        foreach ($targets as $table => $target) {
            $out .= '    ' . var_export($table, true) . ' => ' . self::exportTarget($target, 4) . ",\n";
        }
        return $out . ");\n";
    }

    /**
     * One target as the array literal a migration's TARGET constant holds:
     * one line per column and per index, tokens as Collation constants.
     *
     * @param array $target
     * @param int $indent Of the line the literal starts on.
     * @return string
     */
    public static function exportTarget(array $target, $indent = 0)
    {
        $pad = str_repeat(' ', $indent + 4);
        $lines = array();
        foreach ($target as $key => $value) {
            $head = $pad . var_export($key, true) . ' => ';
            if (in_array($key, array('columns', 'indexes'), true) && !empty($value)) {
                $inner = str_repeat(' ', $indent + 8);
                $entries = array();
                foreach ($value as $name => $entry) {
                    $entryHead = $inner . var_export($name, true) . ' => ';
                    $entries[] = $entryHead . self::export($entry, $indent + 8, strlen($entryHead) - $indent - 8) . ',';
                }
                $lines[] = $head . "array(\n" . implode("\n", $entries) . "\n" . $pad . '),';
                continue;
            }
            $lines[] = $head . self::export($value, $indent + 4, strlen($head) - $indent - 4) . ',';
        }
        return "array(\n" . implode("\n", $lines) . "\n" . str_repeat(' ', $indent) . ')';
    }

    /**
     * @param mixed $value
     * @param int $indent Of the line the value is on.
     * @param int $offset Characters on that line before the value.
     * @return string
     */
    public static function export($value, $indent = 0, $offset = 0)
    {
        if (!is_array($value)) {
            return self::exportScalar($value);
        }
        $inline = self::exportInline($value);
        if ($indent + $offset + strlen($inline) + 1 <= self::EXPORT_WIDTH) {
            return $inline;
        }
        $isList = array_keys($value) === range(0, count($value) - 1);
        $pad = str_repeat(' ', $indent + 4);
        $lines = array();
        foreach ($value as $key => $item) {
            $head = $isList ? '' : var_export($key, true) . ' => ';
            $lines[] = $pad . $head . self::export($item, $indent + 4, strlen($head)) . ',';
        }
        return "array(\n" . implode("\n", $lines) . "\n" . str_repeat(' ', $indent) . ')';
    }

    /**
     * @param array $value
     * @return string
     */
    private static function exportInline(array $value)
    {
        $isList = array_keys($value) === range(0, count($value) - 1);
        $parts = array();
        foreach ($value as $key => $item) {
            $item = is_array($item) ? self::exportInline($item) : self::exportScalar($item);
            $parts[] = $isList ? $item : var_export($key, true) . ' => ' . $item;
        }
        return 'array(' . implode(', ', $parts) . ')';
    }

    /**
     * @param mixed $value
     * @return string
     */
    private static function exportScalar($value)
    {
        $tokens = array(Collation::CI => 'Collation::CI', Collation::BIN => 'Collation::BIN', Collation::ASCII => 'Collation::ASCII');
        if (is_string($value) && isset($tokens[$value])) {
            return $tokens[$value];
        }
        if ($value === null) {
            return 'null';
        }
        return var_export($value, true);
    }
}
