<?php

App::uses('AbstractMigration', 'Migration');
App::uses('ActiveWorkspaceTool', 'Tools');

/**
 * v3 Early Access kept the active workspace as a graph, `{workspace_uuid}`;
 * the workspace is a collection now, `{collection_uuid, graph_uuid}`. Only an
 * instance that ran Early Access holds such a row, so everywhere else this
 * finds nothing and does nothing.
 */
class Migration_20261120_081016_active_workspace_on_a_collection extends AbstractMigration
{
    public $description = 'An active workspace still naming a graph names the collection that graph is drawn on';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    const SETTING = 'active_workspace';

    const OLD_KEY = 'workspace_uuid';

    /** @var array|null */
    private $decision = null;

    /**
     * No DDL. The decision is noted, so that it reaches the update log and the
     * dry run. Counted afresh: an earlier migration of the same run may write
     * the rows this one converts.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $this->decision = self::decide(count($this->rows()));
        $schema->note($this->decision['line']);
    }

    /**
     * @return array
     */
    public function forecast()
    {
        return array($this->decision()['line']);
    }

    /**
     * @return bool
     */
    public function afterUp()
    {
        if ($this->decision()['action'] !== 'convert') {
            return true;
        }
        $UserSetting = ClassRegistry::init('UserSetting');
        $dropped = array();
        // The legacy log's full-change entry would record each choice
        $logged = $UserSetting->Behaviors->enabled('SysLogLogable.SysLogLogable');
        $UserSetting->Behaviors->disable('SysLogLogable.SysLogLogable');
        try {
            foreach ($this->rows() as $row) {
                $value = $this->resolve($row);
                if ($value === null) {
                    $dropped[] = $row['id'];
                } elseif (!$UserSetting->setSettingInternal($row['user_id'], self::SETTING, $value)) {
                    return false;
                }
            }
        } finally {
            if ($logged) {
                $UserSetting->Behaviors->enable('SysLogLogable.SysLogLogable');
            }
        }
        if (empty($dropped)) {
            return true;
        }
        return (bool)$UserSetting->deleteAll(array('UserSetting.id' => $dropped), false, false);
    }

    /**
     * What to do, from what the instance holds.
     *
     * @param int $rows Active workspace settings still naming a graph
     * @return array action ('none' or 'convert'), line
     */
    public static function decide($rows)
    {
        if ($rows === 0) {
            return array(
                'action' => 'none',
                'line' => 'No active workspace still names a graph: there is nothing to convert.',
            );
        }
        return array(
            'action' => 'convert',
            'line' => sprintf('From v3 Early Access: %d active workspace setting(s) still name a graph. Each becomes the collection that graph is drawn on, laid out by it when it is the user\'s organisation\'s, if the user may edit that collection; the others are cleared.', $rows),
        );
    }

    /**
     * @param mixed $stored The setting's value as stored, JSON
     * @return string|false|null False when it is not in the Early Access
     *   shape, else the graph it names, lowercase, or null when it names none
     */
    public static function named($stored)
    {
        $value = is_string($stored) ? json_decode($stored, true) : $stored;
        if (!is_array($value) || !array_key_exists(self::OLD_KEY, $value) || array_key_exists('collection_uuid', $value)) {
            return false;
        }
        $uuid = $value[self::OLD_KEY];
        if (!is_string($uuid) || preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid) !== 1) {
            return null;
        }
        return strtolower($uuid);
    }

    /**
     * What a setting naming this graph becomes: the collection it is
     * drawn on, when the user may edit it, with the graph when it is their
     * organisation's on it. A graph on an event or a cluster, or gone, ends it.
     *
     * @param array|null $graph object_type, object_uuid; null when it is gone
     * @param array|null $found ActiveWorkspaceTool::lookUp() for the user, that
     *   collection and the graph
     * @return array|null {collection_uuid, graph_uuid}, or null to drop the row
     */
    public static function converted($graph, $found = null)
    {
        if ($graph === null || $graph['object_type'] !== 'Collection' || $found === null) {
            return null;
        }
        list($collection, $kept, $refusal) = $found;
        if ($collection === null || $refusal === 'collection' || $refusal === 'edit') {
            return null;
        }
        return array(
            'collection_uuid' => $collection['uuid'],
            'graph_uuid' => $refusal === null && $kept !== null ? $kept['uuid'] : null,
        );
    }

    /**
     * @param array $row id, user_id, value
     * @return array|null
     */
    private function resolve(array $row)
    {
        $uuid = self::named($row['value']);
        if ($uuid === null) {
            return null;
        }
        $found = ClassRegistry::init('Graph')->find('first', array(
            'conditions' => array('Graph.uuid' => array_values(array_unique(array($uuid, strtoupper($uuid))))),
            'fields' => array('Graph.uuid', 'Graph.object_type', 'Graph.object_uuid'),
            'recursive' => -1,
            'callbacks' => false,
        ));
        $graph = empty($found) ? null : $found['Graph'];
        if ($graph === null || $graph['object_type'] !== 'Collection') {
            return self::converted($graph);
        }
        $user = $row['user_id'] > 0 ? ClassRegistry::init('User')->getAuthUser($row['user_id']) : null;
        if (empty($user)) {
            return null;
        }
        return self::converted($graph, ActiveWorkspaceTool::lookUp($user, $graph['object_uuid'], $uuid));
    }

    /**
     * @return array [{id, user_id, value}] the settings still in the Early
     *   Access shape
     */
    private function rows()
    {
        $rows = ClassRegistry::init('UserSetting')->find('all', array(
            'conditions' => array(
                'UserSetting.setting' => self::SETTING,
                'UserSetting.value LIKE' => '%"' . self::OLD_KEY . '"%',
            ),
            'fields' => array('UserSetting.id', 'UserSetting.user_id', 'UserSetting.value'),
            'order' => array('UserSetting.id' => 'ASC'),
            'recursive' => -1,
            'callbacks' => false,
        ));
        $old = array();
        foreach ($rows as $row) {
            if (self::named($row['UserSetting']['value']) !== false) {
                $old[] = array(
                    'id' => (int)$row['UserSetting']['id'],
                    'user_id' => (int)$row['UserSetting']['user_id'],
                    'value' => $row['UserSetting']['value'],
                );
            }
        }
        return $old;
    }

    /**
     * @return array
     */
    private function decision()
    {
        if ($this->decision === null) {
            $this->decision = self::decide(count($this->rows()));
        }
        return $this->decision;
    }
}
