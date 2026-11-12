<?php

App::uses('AbstractMigration', 'Migration');
App::uses('Collation', 'Migration');

/**
 * Galaxy and organisation text columns compare case-insensitively
 */
class Migration_20261112_105309_galaxy_org_text_case_insensitive extends AbstractMigration
{
    public $description = 'Galaxy and organisation text columns compare case-insensitively';

    /**
     * True if this touches a table the session data is built from, and every
     * user therefore has to log in again.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * organisations.name stays case-sensitive: it carries a unique index, and
     * sync captures organisations without a uuid by name.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->table('galaxies')
            ->changeColumn('name', 'string', $this->ci(255, false, ''))
            ->changeColumn('type', 'string', $this->ci(255, false, null))
            ->changeColumn('description', 'text', $this->ci(null, false, null))
            ->changeColumn('category', 'string', $this->ci(255, true, null))
            ->changeColumn('sub_category', 'string', $this->ci(255, true, null));
        $schema->table('galaxy_clusters')
            ->changeColumn('type', 'string', $this->ci(255, false, null))
            ->changeColumn('value', 'text', $this->ci(null, false, null))
            ->changeColumn('source', 'string', $this->ci(255, false, ''))
            ->changeColumn('authors', 'text', $this->ci(null, false, null));
        $schema->table('galaxy_elements')
            ->changeColumn('key', 'string', $this->ci(255, false, ''))
            ->changeColumn('value', 'text', $this->ci(null, false, null));
        $schema->table('organisations')
            ->changeColumn('description', 'text', $this->ci(null, true, null))
            ->changeColumn('type', 'string', $this->ci(255, false, ''))
            ->changeColumn('nationality', 'string', $this->ci(255, false, ''))
            ->changeColumn('sector', 'string', $this->ci(255, false, ''));
    }

    /**
     * @param int|null $length
     * @param bool $null
     * @param string|null $default
     * @return array
     */
    private function ci($length, $null, $default)
    {
        $options = array('null' => $null, 'default' => $default, 'collate' => Collation::CI);
        if ($length !== null) {
            $options['length'] = $length;
        }
        return $options;
    }
}
