<?php

App::uses('ClassRegistry', 'Utility');
App::uses('Collation', 'Migration');
App::uses('SchemaInspector', 'Migration');

/**
 * Merges the tags whose names a unique key over tags.name would refuse once
 * the column compares under a given collation, each group into its oldest
 * member.
 *
 * Every tag_id column in the schema is repointed, link rows that became
 * duplicates are collapsed, server push rules (which hold local tag ids) are
 * rewritten, the merged rows are deleted, and each merge is written to the
 * log. Server pull rules and feed rules hold remote tag names and are left
 * alone. A re-run finds nothing left to merge.
 *
 * On PostgreSQL the names are compared through lower(), as the unique index
 * there compares them.
 *
 * Migration_20260915_131521_tags_name_case_insensitive carries its own copy
 * of this routine and stays as it was released.
 */
class TagNameMerger
{
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

    /** @var SchemaInspector */
    private $inspector;

    /** @var string|null The MySQL collation compared under; null on PostgreSQL. */
    private $collation;

    /** @var Tag */
    private $Tag;

    /** @var Log */
    private $Log;

    /**
     * @param SchemaInspector $inspector
     * @param string $collate What tags.name compares under afterwards: a
     *   Collation token or a MySQL collation name. Unused on PostgreSQL.
     * @throws MigrationDeferredException When a token cannot be resolved for
     *   this server.
     */
    public function __construct(SchemaInspector $inspector, $collate)
    {
        $this->inspector = $inspector;
        if ($inspector->flavour() === SchemaInspector::FLAVOUR_MYSQL) {
            $this->collation = Collation::isToken($collate)
                ? Collation::forServer($collate, $inspector->serverVersion())['collate']
                : $collate;
        }
    }

    /**
     * @return int Tags merged into another.
     */
    public function merge()
    {
        if (!$this->inspector->hasTable('tags')) {
            return 0;
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
        $merged = 0;
        foreach ($groups as $group) {
            $merged += $this->mergeInto((int)$group['keep_id']);
        }
        return $merged;
    }

    /**
     * An expression compared the way the column will be.
     *
     * @param string $expression A quoted column or literal.
     * @return string
     */
    private function folded($expression)
    {
        if ($this->collation !== null) {
            return 'CONVERT(' . $expression . ' USING utf8mb4) COLLATE ' . $this->collation;
        }
        return 'lower(' . $expression . ')';
    }

    /**
     * Merges every tag whose name equals the given tag's name under the
     * target comparison into that tag.
     *
     * @param int $keepId
     * @return int Tags merged.
     */
    private function mergeInto($keepId)
    {
        $db = $this->Tag->getDataSource();
        $id = $db->name('id');
        $name = $db->name('name');
        $tags = $db->name('tags');

        $keep = $this->rows(sprintf('SELECT %s, %s FROM %s WHERE %s = %d', $id, $name, $tags, $id, $keepId));
        if (empty($keep)) {
            return 0;
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
            return 0;
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
                    'Merged tag "%s" (id %s) into "%s" (id %s): the names are equal under %s, which tag names are compared with from now on.',
                    $loser['name'],
                    $loserId,
                    $keepName,
                    $keepId,
                    $this->collation === null ? 'lower()' : $this->collation
                ),
                'change' => empty($changes) ? __('No references to repoint.') : implode(', ', $changes),
            ));
        }
        return count($losers);
    }

    /**
     * @return array Every table with a tag_id column, as the schema has it now.
     */
    private function tablesWithTagId()
    {
        $tables = array();
        foreach ($this->inspector->tables() as $table) {
            if ($this->inspector->hasColumn($table, 'tag_id')) {
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
