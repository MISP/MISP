<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Create the value_ip_ranges IP facet of attribute_values
 */
class Migration_20261004_093106_create_value_ip_ranges extends AbstractMigration
{
    public $description = 'Create the value_ip_ranges IP facet of attribute_values';

    public $requiresLogout = false;

    const TABLE = 'value_ip_ranges';

    /**
     * IPv4 is stored v4-mapped, so both ends are always 16 bytes. value_id
     * closes start_end so that range lookups return it from the index alone.
     *
     * Guarded, so a retry after a partial failure declares only what is
     * still missing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $inspector = $this->inspector();
        $startEnd = array('ip_start', 'ip_end', 'value_id');

        if (!$inspector->hasTable(self::TABLE)) {
            $schema->createTable(self::TABLE, array(
                'id' => array('type' => 'biginteger', 'key' => 'primary', 'unsigned' => true, 'null' => false),
                'value_id' => array('type' => 'biginteger', 'unsigned' => true, 'null' => false),
                'ip_start' => array('type' => 'varbinary', 'length' => 16, 'null' => false),
                'ip_end' => array('type' => 'varbinary', 'length' => 16, 'null' => false),
                'prefix' => array('type' => 'tinyinteger', 'unsigned' => true, 'null' => false),
            ), array(
                'indexes' => array(
                    'value_id' => array('unique' => true),
                    'start_end' => array('column' => $startEnd),
                ),
                'engine' => 'InnoDB',
                'charset' => 'utf8mb4',
            ));
            return;
        }
        $table = $schema->table(self::TABLE);
        if (!$inspector->hasIndex(self::TABLE, 'value_id', true)) {
            $table->addIndex('value_id', array('unique' => true));
        }
        if (!$inspector->hasIndex(self::TABLE, $startEnd)) {
            $table->addIndex($startEnd, array('name' => 'start_end'));
        }
    }
}
