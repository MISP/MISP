<?php

App::uses('AbstractMigration', 'Migration');
App::uses('Validation', 'Utility');
App::uses('Workspace', 'Model');

/**
 * Carry what v3 Early Access stored under the analyst graph's names over to
 * the workspace's. Only an instance that ran it holds any: 2.5 has neither the
 * type nor the setting and a fresh install starts empty, so everywhere else
 * this finds nothing and does nothing.
 */
class Migration_20261022_123413_early_access_workspace_names extends AbstractMigration
{
    public $description = 'Carry what v3 Early Access stored under the analyst graph names over to workspaces';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    const OLD_TYPE = 'Graph';

    const NEW_TYPE = 'Workspace';

    const OLD_SETTING = 'intelligence_graph_active';

    /** The analyst-data columns that name the type of the record pointed at. */
    const TARGETS = array(
        array('Note', 'object_type'),
        array('Opinion', 'object_type'),
        array('Relationship', 'object_type'),
        array('Relationship', 'related_object_type'),
    );

    /** @var array|null */
    private $decision = null;

    /**
     * No DDL. The decision is noted, so that it reaches the update log and the
     * dry run.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->note($this->decision()['line']);
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
        if ($this->decision()['action'] !== 'rename') {
            return true;
        }
        foreach (self::TARGETS as $target) {
            list($model, $column) = $target;
            $Model = ClassRegistry::init($model);
            $renamed = $Model->updateAll(
                array($Model->alias . '.' . $column => $Model->getDataSource()->value(self::NEW_TYPE, 'string')),
                array($Model->alias . '.' . $column => self::OLD_TYPE)
            );
            if (!$renamed) {
                return false;
            }
        }
        return $this->moveActiveSettings();
    }

    /**
     * What to do, from what the instance holds.
     *
     * @param array $state targets ("Model.column" => rows naming the old
     *   type), settings (rows of the old setting)
     * @return array action ('none' or 'rename'), line
     */
    public static function decide(array $state)
    {
        $references = array_sum($state['targets']);
        if ($references === 0 && $state['settings'] === 0) {
            return array(
                'action' => 'none',
                'line' => 'Nothing is stored under the analyst graph names: this instance did not run v3 Early Access with analyst graphs, so there is nothing to carry over.',
            );
        }
        $parts = array();
        if ($references > 0) {
            $parts[] = sprintf('%d analyst data reference(s) to an analyst graph now name a %s', $references, self::NEW_TYPE);
        }
        if ($state['settings'] > 0) {
            $parts[] = sprintf('%d active analyst graph setting(s) move to the active workspace', $state['settings']);
        }
        return array('action' => 'rename', 'line' => 'From v3 Early Access: ' . implode('; ', $parts) . '.');
    }

    /**
     * Each user keeps the analyst graph they had active as their active
     * workspace, unless they have picked one since.
     *
     * @return bool
     */
    private function moveActiveSettings()
    {
        $UserSetting = ClassRegistry::init('UserSetting');
        $Workspace = ClassRegistry::init('Workspace');
        $rows = $UserSetting->find('all', array(
            'conditions' => array('UserSetting.setting' => self::OLD_SETTING),
            'fields' => array('UserSetting.user_id', 'UserSetting.value'),
            'recursive' => -1,
            'callbacks' => false,
        ));
        foreach ($rows as $row) {
            $userId = (int)$row['UserSetting']['user_id'];
            $value = json_decode((string)$row['UserSetting']['value'], true);
            $uuid = is_array($value) ? ($value['graph_uuid'] ?? null) : null;
            if (!is_string($uuid) || !Validation::uuid($uuid)) {
                continue;
            }
            if ($UserSetting->getValueForUser($userId, Workspace::ACTIVE_SETTING) !== null) {
                continue;
            }
            if (!$Workspace->storeActive(array('id' => $userId), $uuid)) {
                return false;
            }
        }
        return (bool)$UserSetting->deleteAll(array('UserSetting.setting' => self::OLD_SETTING), false, false);
    }

    /**
     * @return array
     */
    private function decision()
    {
        if ($this->decision === null) {
            $this->decision = self::decide($this->state());
        }
        return $this->decision;
    }

    /**
     * @return array
     */
    private function state()
    {
        $targets = array();
        foreach (self::TARGETS as $target) {
            list($model, $column) = $target;
            $Model = ClassRegistry::init($model);
            $targets[$model . '.' . $column] = (int)$Model->find('count', array(
                'conditions' => array($Model->alias . '.' . $column => self::OLD_TYPE),
                'recursive' => -1,
                'callbacks' => false,
            ));
        }
        $settings = (int)ClassRegistry::init('UserSetting')->find('count', array(
            'conditions' => array('UserSetting.setting' => self::OLD_SETTING),
            'recursive' => -1,
            'callbacks' => false,
        ));
        return array('targets' => $targets, 'settings' => $settings);
    }
}
