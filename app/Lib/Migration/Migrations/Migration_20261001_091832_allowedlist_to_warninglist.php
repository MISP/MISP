<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Convert the signature allowedlist into a warninglist and drop its table
 */
class Migration_20261001_091832_allowedlist_to_warninglist extends AbstractMigration
{
    public $description = 'Convert the signature allowedlist into a warninglist and drop its table';

    /**
     * Nothing the session data is built from changes.
     *
     * @var bool
     */
    public $requiresLogout = false;

    const WARNINGLIST_NAME = 'Signature allowedlist (migrated)';

    /** @var Warninglist */
    private $Warninglist;

    /**
     * Copy every allowedlist regex into one custom, enabled warninglist of
     * type regex matching all attribute types. Entries that are not a valid
     * regular expression would make the whole save fail, so they are left
     * out and named in the log instead. A retry after the drop failed finds
     * the warninglist already there and does not create it twice.
     *
     * @return bool
     */
    public function beforeUp()
    {
        if (!$this->inspector()->hasTable('allowedlist')) {
            return true;
        }
        $this->Warninglist = ClassRegistry::init('Warninglist');
        $exists = $this->Warninglist->hasAny(
            array('Warninglist.name' => self::WARNINGLIST_NAME)
        );
        if ($exists) {
            return true;
        }

        $db = $this->Warninglist->getDataSource();
        $rows = $this->Warninglist->query(sprintf(
            'SELECT %s FROM %s ORDER BY %s',
            $db->name('name'),
            $db->name('allowedlist'),
            $db->name('id')
        ), false);

        $entries = array();
        $invalid = array();
        $composite = array();
        foreach ((array)$rows as $row) {
            $regex = trim((string)array_merge(...array_values($row))['name']);
            if ($regex === '') {
                continue;
            }
            if (@preg_match($regex, '') === false) {
                $invalid[] = $regex;
                continue;
            }
            if (str_contains($regex, '|')) {
                $composite[] = $regex;
            }
            $entries[$regex] = array('value' => $regex);
        }
        if (empty($entries)) {
            if (!empty($invalid)) {
                $this->logConversion(__('No allowedlist entry could be migrated.'), $invalid, array());
            }
            return true;
        }

        $saved = $this->Warninglist->save(array(
            'Warninglist' => array(
                'name' => self::WARNINGLIST_NAME,
                'description' => __('Entries migrated from the signature allowedlist, which has been removed. Matching attributes are flagged, and are left out of exports only when enforceWarninglist is set.'),
                'version' => 1,
                'type' => 'regex',
                'category' => Warninglist::CATEGORY_FALSE_POSITIVE,
                'enabled' => 1,
                'default' => 0,
            ),
            'WarninglistEntry' => array_values($entries),
            'WarninglistType' => array(array('type' => 'ALL')),
        ));
        if (empty($saved)) {
            return false;
        }
        $this->logConversion(
            __('Migrated %s allowedlist entries into the warninglist "%s".', count($entries), self::WARNINGLIST_NAME),
            $invalid,
            $composite
        );
        return true;
    }

    /**
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        if ($this->inspector()->hasTable('allowedlist')) {
            $schema->dropTable('allowedlist');
        }
    }

    /**
     * @param string $title
     * @param array $invalid Entries left out as invalid regular expressions.
     * @param array $composite Entries containing a pipe: warninglists match
     *   each half of a composite value on its own, the allowedlist matched
     *   the whole value, so these may stop matching.
     * @return void
     */
    private function logConversion($title, array $invalid, array $composite)
    {
        $change = array();
        if (!empty($invalid)) {
            $change[] = __('Not migrated, invalid regular expression: %s', implode(', ', $invalid));
        }
        if (!empty($composite)) {
            $change[] = __('Review, composite values are now matched per half: %s', implode(', ', $composite));
        }
        $Log = ClassRegistry::init('Log');
        $Log->create();
        $Log->saveOrFailSilently(array(
            'org' => 'SYSTEM',
            'model' => 'Warninglist',
            'model_id' => (int)$this->Warninglist->id,
            'email' => 'SYSTEM',
            'action' => 'update_database',
            'user_id' => 0,
            'title' => $title,
            'change' => implode("\n", $change),
        ));
    }
}
