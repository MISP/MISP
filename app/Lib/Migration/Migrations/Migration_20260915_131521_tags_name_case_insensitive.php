<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Make tags.name case-insensitive, merging names that collide
 */
class Migration_20260915_131521_tags_name_case_insensitive extends AbstractMigration
{
    public $description = 'Make tags.name case-insensitive, merging names that collide';

    /**
     * Nothing the session data is built from changes.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * The collation tags.name moves to on MySQL. Names that are equal under
     * it are what the unique key will refuse, so the merge groups by it too.
     */
    const COLLATION = 'utf8mb4_unicode_ci';

    /**
     * The PostgreSQL spelling of the same uniqueness: a unique index over
     * lower(name). Tag::nameCondition() compares against it.
     */
    const PGSQL_INDEX = 'idx_tags_name_lower';

    /**
     * Link tables whose (owner, tag_id) pair may not repeat once a merged
     * tag's rows are repointed onto the survivor.
     */
    const LINK_TABLES = array(
        'event_tags' => 'event_id',
        'attribute_tags' => 'attribute_id',
        'event_report_tags' => 'event_report_id',
        'tag_collection_tags' => 'tag_collection_id',
        'favourite_tags' => 'user_id',
        'galaxy_cluster_relation_tags' => 'galaxy_cluster_relation_id',
        'template_tags' => 'template_id',
    );

    /** @var Tag */
    private $Tag;

    /** @var Log */
    private $Log;

    /**
     * Merge the names the new uniqueness would refuse.
     *
     * The unique key on tags.name becomes case-insensitive, so it would
     * refuse `tlp:red` next to `TLP:RED`. Tag::captureTag() has matched names
     * through LOWER() since 2016 and never created such pairs, but the plain
     * isUnique rule and the REST existing-tag check in TagsController::add()
     * compared byte-for-byte under utf8mb3_bin, so they exist in the wild.
     * Instances installed before 2.5.0 never got the unique key at all
     * (MYSQL.sql gained it in 2024 with no update behind it), so there the
     * ALTER would not even complain.
     *
     * Every group of names that are equal under the target comparison is
     * merged into its oldest member: each tag_id column in the schema is
     * repointed, link rows that became duplicates are collapsed, server push
     * rules (which hold local tag ids) are rewritten, the merged rows are
     * deleted, and each merge is written to the log. Server pull rules and
     * feed rules hold remote tag names and are left alone. Replayable: a
     * re-run finds nothing to merge, and an instance already case-insensitive
     * - one that ran this as legacy update 160 - is not even looked at.
     *
     * @return bool
     */
    public function beforeUp()
    {
        if ($this->isCaseInsensitiveAlready()) {
            return true;
        }
        $this->Tag = ClassRegistry::init('Tag');
        $this->Log = ClassRegistry::init('Log');
        $db = $this->Tag->getDataSource();
        $groups = $this->rows(sprintf(
            'SELECT MIN(%s) AS keep_id FROM %s GROUP BY %s HAVING COUNT(*) > 1',
            $db->name('id'),
            $db->name('tags'),
            $this->folded($db->name('name'))
        ));
        foreach ($groups as $group) {
            $this->mergeInto((int)$group['keep_id']);
        }
        return true;
    }

    /**
     * Every step is guarded, so a retry after a partial failure declares
     * only what is still missing, and an instance that ran legacy update 160
     * declares nothing.
     *
     * The dry run renders what would run on this instance's schema: on a
     * MySQL instance the PostgreSQL half shows the collation change as that
     * grammar drops it, and only a PostgreSQL instance shows its own index.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        $tags = $schema->table('tags');

        // The unique key first, where it is missing: exact-case uniqueness
        // holds now that beforeUp() has merged the collisions, and the
        // collation change below rebuilds the key case-insensitively.
        if (!$inspector->hasIndex('tags', 'name', true)) {
            $plain = $inspector->indexNameForColumn('tags', 'name', false);
            if ($plain !== null) {
                $tags->dropIndex($plain);
            }
            $tags->addIndex('name', array('unique' => true));
        }

        $column = $inspector->column('tags', 'name');
        if (isset($column['collate'])) {
            // MySQL: the collation is the case-insensitivity. ROW_FORMAT
            // first - a unique key over 255 utf8mb4 characters needs the
            // large index prefix only DYNAMIC rows allow, and a table created
            // under an older default is still COMPACT.
            if ($column['collate'] !== self::COLLATION) {
                $schema->rawSql(array(
                    'mysql' => 'ALTER TABLE `tags` ROW_FORMAT=DYNAMIC;',
                    'pgsql' => array(),
                ));
                $tags->changeColumn('name', 'string', array(
                    'length' => 255,
                    'null' => false,
                    'default' => null,
                    'charset' => 'utf8mb4',
                    'collate' => self::COLLATION,
                ));
            }
        } elseif (!$inspector->hasNamedIndex('tags', self::PGSQL_INDEX)) {
            // PostgreSQL reports no collation, and none does this there: the
            // uniqueness is an index over lower(name), and Tag::nameCondition()
            // spells its comparison so the planner takes it.
            $schema->rawSql(array(
                'mysql' => array(),
                'pgsql' => sprintf(
                    'CREATE UNIQUE INDEX "%s" ON "tags" (lower("name"));',
                    self::PGSQL_INDEX
                ),
            ));
        }
    }

    /**
     * @return bool Whether tags.name already compares case-insensitively and
     *   uniquely, so there is nothing to merge.
     */
    private function isCaseInsensitiveAlready()
    {
        $inspector = $this->inspector();
        $column = $inspector->column('tags', 'name');
        if ($column === null) {
            return true;
        }
        if (isset($column['collate'])) {
            return $column['collate'] === self::COLLATION
                && $inspector->hasIndex('tags', 'name', true);
        }
        return $inspector->hasNamedIndex('tags', self::PGSQL_INDEX);
    }

    /**
     * An expression compared the way the column will be once this has run.
     *
     * @param string $expression A quoted column or literal.
     * @return string
     */
    private function folded($expression)
    {
        if ($this->inspector()->flavour() === SchemaInspector::FLAVOUR_MYSQL) {
            return 'CONVERT(' . $expression . ' USING utf8mb4) COLLATE ' . self::COLLATION;
        }
        return 'lower(' . $expression . ')';
    }

    /**
     * Merges every tag whose name equals the given tag's name under the
     * target comparison into that tag.
     *
     * @param int $keepId
     * @return void
     */
    private function mergeInto($keepId)
    {
        $db = $this->Tag->getDataSource();
        $id = $db->name('id');
        $name = $db->name('name');
        $tags = $db->name('tags');

        $keep = $this->rows(sprintf('SELECT %s, %s FROM %s WHERE %s = %d', $id, $name, $tags, $id, $keepId));
        if (empty($keep)) {
            return;
        }
        $keepName = $keep[0]['name'];
        $losers = $this->rows(sprintf(
            'SELECT %s, %s FROM %s WHERE %s <> %d AND %s = %s ORDER BY %s',
            $id,
            $name,
            $tags,
            $id,
            $keepId,
            $this->folded($name),
            $this->folded($db->value($keepName, 'string')),
            $id
        ));
        if (empty($losers)) {
            return;
        }
        $tagIdTables = $this->tablesWithTagId();
        foreach ($losers as $loser) {
            $loserId = (int)$loser['id'];
            $changes = array();
            foreach ($tagIdTables as $table) {
                $affected = $this->execute(sprintf(
                    'UPDATE %s SET %s = %d WHERE %s = %d',
                    $db->name($table),
                    $db->name('tag_id'),
                    $keepId,
                    $db->name('tag_id'),
                    $loserId
                ));
                if ($affected) {
                    $changes[] = $table . ': ' . $affected;
                }
            }
            foreach (self::LINK_TABLES as $table => $owner) {
                if (!in_array($table, $tagIdTables, true)) {
                    continue;
                }
                $removed = $this->removeDuplicateLinks($table, $owner, $keepId);
                if ($removed) {
                    $changes[] = $table . ': ' . $removed . ' duplicate link(s) removed';
                }
            }
            $rewritten = $this->replaceTagIdInPushRules($loserId, $keepId);
            if ($rewritten) {
                $changes[] = 'servers push rules rewritten: ' . $rewritten;
            }
            $this->execute(sprintf('DELETE FROM %s WHERE %s = %d', $tags, $id, $loserId));
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
                'org' => 'SYSTEM',
                'model' => 'Tag',
                'model_id' => $keepId,
                'email' => 'SYSTEM',
                'action' => 'update_database',
                'user_id' => 0,
                'title' => __(
                    'Merged tag "%s" (id %s) into "%s" (id %s): the names are equal now that tag names are case-insensitive.',
                    $loser['name'],
                    $loserId,
                    $keepName,
                    $keepId
                ),
                'change' => empty($changes) ? __('No references to repoint.') : implode(', ', $changes),
            ));
        }
    }

    /**
     * @return array Every table with a tag_id column, as the schema has it now.
     */
    private function tablesWithTagId()
    {
        $inspector = $this->inspector();
        $tables = array();
        foreach ($inspector->tables() as $table) {
            if ($inspector->hasColumn($table, 'tag_id')) {
                $tables[] = $table;
            }
        }
        return $tables;
    }

    /**
     * Once a merged tag's links point at the survivor, an owner that carried
     * both tags holds the survivor twice. The later row goes. A select and a
     * delete rather than one self-joined DELETE, which the two engines spell
     * differently.
     *
     * @param string $table
     * @param string $owner The column naming what the tag is attached to.
     * @param int $keepId
     * @return int Rows removed.
     */
    private function removeDuplicateLinks($table, $owner, $keepId)
    {
        $db = $this->Tag->getDataSource();
        $rows = $this->rows(sprintf(
            'SELECT a.%1$s AS id FROM %2$s a JOIN %2$s b ON a.%3$s = b.%3$s AND a.%4$s = b.%4$s AND a.%1$s > b.%1$s WHERE a.%4$s = %5$d',
            $db->name('id'),
            $db->name($table),
            $db->name($owner),
            $db->name('tag_id'),
            $keepId
        ));
        $ids = array_map('intval', array_column($rows, 'id'));
        $removed = 0;
        foreach (array_chunk(array_unique($ids), 500) as $chunk) {
            $removed += $this->execute(sprintf(
                'DELETE FROM %s WHERE %s IN (%s)',
                $db->name($table),
                $db->name('id'),
                implode(', ', $chunk)
            ));
        }
        return $removed;
    }

    /**
     * Server push rules filter on local tag ids; a merged tag's id is
     * replaced by the survivor's so the rule keeps matching.
     *
     * @param int $from
     * @param int $to
     * @return int Servers rewritten.
     */
    private function replaceTagIdInPushRules($from, $to)
    {
        $db = $this->Tag->getDataSource();
        $servers = $this->rows(sprintf(
            'SELECT %s, %s FROM %s WHERE %s LIKE %s',
            $db->name('id'),
            $db->name('push_rules'),
            $db->name('servers'),
            $db->name('push_rules'),
            $db->value('%"tags"%', 'string')
        ));
        $rewritten = 0;
        foreach ($servers as $server) {
            $rules = json_decode((string)$server['push_rules'], true);
            if (!is_array($rules) || empty($rules['tags']) || !is_array($rules['tags'])) {
                continue;
            }
            $changed = false;
            foreach ($rules['tags'] as $operator => $ids) {
                if (!is_array($ids)) {
                    continue;
                }
                $replaced = array();
                foreach ($ids as $tagId) {
                    if (is_numeric($tagId) && (int)$tagId === $from) {
                        $tagId = is_string($tagId) ? (string)$to : $to;
                        $changed = true;
                    }
                    if (!in_array($tagId, $replaced, true)) {
                        $replaced[] = $tagId;
                    }
                }
                $rules['tags'][$operator] = $replaced;
            }
            if (!$changed) {
                continue;
            }
            $this->execute(sprintf(
                'UPDATE %s SET %s = %s WHERE %s = %d',
                $db->name('servers'),
                $db->name('push_rules'),
                $db->value(json_encode($rules), 'string'),
                $db->name('id'),
                (int)$server['id']
            ));
            $rewritten++;
        }
        return $rewritten;
    }

    /**
     * A raw SELECT, each row flattened across the per-table grouping the
     * datasource applies (`['tags' => [...]]`, `[0 => [...]]`).
     *
     * @param string $sql
     * @return array
     */
    private function rows($sql)
    {
        $rows = $this->Tag->query($sql, false);
        $flat = array();
        foreach ((array)$rows as $row) {
            $flat[] = array_merge(...array_values($row));
        }
        return $flat;
    }

    /**
     * A raw statement, answering how many rows it touched.
     *
     * @param string $sql
     * @return int
     */
    private function execute($sql)
    {
        $this->Tag->query($sql, false);
        return (int)$this->Tag->getDataSource()->lastAffected();
    }
}
