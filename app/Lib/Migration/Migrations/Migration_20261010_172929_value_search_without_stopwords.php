<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Rebuild the value_search index of attribute_values without stopwords
 */
class Migration_20261010_172929_value_search_without_stopwords extends AbstractMigration
{
    public $description = 'Rebuild the value_search index of attribute_values without stopwords';

    public $requiresLogout = false;

    const TABLE = 'attribute_values';

    /**
     * InnoDB applies its stopword list when a FULLTEXT index is built, and an
     * index built with it holds no `com`, `www` or `the`. PostgreSQL's trigram
     * index has no such list.
     *
     * The table is rebuilt rather than the index dropped and added: on MariaDB
     * 10.11 a FULLTEXT index filled row by row, dropped and added again,
     * matches nothing.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $mysql = array('SET SESSION innodb_ft_enable_stopword = 0;');
        if ($this->inspector()->hasNamedIndex(self::TABLE, 'value_search')) {
            $mysql[] = sprintf('ALTER TABLE `%s` FORCE;', self::TABLE);
        } else {
            $mysql[] = sprintf('ALTER TABLE `%s` ADD FULLTEXT INDEX `value_search` (`value`);', self::TABLE);
        }
        $mysql[] = 'SET SESSION innodb_ft_enable_stopword = DEFAULT;';
        $schema->rawSql(array(
            'mysql' => $mysql,
            'pgsql' => array(),
        ));
    }
}
