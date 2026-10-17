<?php

App::uses('Collation', 'Migration');
App::uses('TableMigration', 'Migration');
App::uses('TagNameMerger', 'Migration');

/**
 * Schema modernisation: tags
 */
class Migration_20261016_180323_schema_v3_tags extends TableMigration
{
    public $description = 'Schema modernisation: tags';

    const TABLE = 'tags';

    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'colour' => array('type' => 'string', 'length' => 7, 'null' => false, 'collate' => Collation::BIN),
            'exportable' => array('type' => 'boolean', 'null' => false),
            'org_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'user_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'hide_tag' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'numerical_value' => array('type' => 'integer', 'null' => true),
            'is_galaxy' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'is_custom_galaxy' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'local_only' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
        ),
        'indexes' => array(
            'idx_tags_name_lower' => array(
                'mysql' => false,
                'pgsql' => array('sql' => 'CREATE UNIQUE INDEX %1$s ON %2$s (lower("name"));'),
            ),
            'name' => array('column' => array('name'), 'unique' => true),
            'numerical_value' => array('column' => array('numerical_value')),
            'org_id' => array('column' => array('org_id')),
            'user_id' => array('column' => array('user_id')),
        ),
        'retired' => array(),
    );

    /**
     * Names the target collation compares as equal would fail the unique key
     * on name: they are merged first.
     *
     * @return bool
     */
    public function beforeUp()
    {
        (new TagNameMerger($this->inspector(), self::TARGET['columns']['name']['collate']))->merge();
        return parent::beforeUp();
    }
}
