<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Analyst data pointing at a workspace points at a saved graph again: the
 * analyst graph record is called Graph once more. Only an instance that ran v3
 * Early Access holds such a reference, so everywhere else this finds nothing
 * and does nothing.
 */
class Migration_20261028_083019_analyst_graph_names_back extends AbstractMigration
{
    public $description = 'Analyst data pointing at a workspace points at a saved graph again';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    const OLD_TYPE = 'Workspace';

    const NEW_TYPE = 'Graph';

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
     * dry run. Counted afresh: the migration before this one writes the very
     * references it renames.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $this->decision = self::decide($this->state());
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
        return true;
    }

    /**
     * What to do, from what the instance holds.
     *
     * @param array $targets "Model.column" => rows naming the old type
     * @return array action ('none' or 'rename'), line
     */
    public static function decide(array $targets)
    {
        $references = array_sum($targets);
        if ($references === 0) {
            return array(
                'action' => 'none',
                'line' => 'No analyst data points at a workspace: there is nothing to rename.',
            );
        }
        return array(
            'action' => 'rename',
            'line' => sprintf('%d analyst data reference(s) to a workspace now name a saved graph (%s) again.', $references, self::NEW_TYPE),
        );
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
        return $targets;
    }
}
