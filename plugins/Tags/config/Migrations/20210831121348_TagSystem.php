<?php
declare(strict_types=1);

use Migrations\AbstractMigration;


class TagSystem extends AbstractMigration
{
    public function change() {
        $tags = $this->table('tags_tags');
        $tags->addColumn('namespace', 'string', [
                'default' => null,
                'limit' => 191,
                'null' => true,
            ])
            ->addColumn('predicate', 'string', [
                'default' => null,
                'limit' => 191,
                'null' => true,
            ])
            ->addColumn('value', 'string', [
                'default' => null,
                'limit' => 191,
                'null' => true,
            ])
            ->addColumn('name', 'string', [
                'default' => null,
                'limit' => 191,
                'null' => false,
            ])
            ->addColumn('colour', 'string', [
                'default' => null,
                'limit' => 7,
                'null' => false,
            ])
            ->addColumn('counter', 'integer', [
                'default' => 0,
                'length' => 11,
                'null' => false,
                'signed' => false,
                'comment' => 'Field used by the CounterCache behaviour to count the occurence of tags'
            ])
            ->addColumn('created', 'datetime', [
                'default' => null,
                'null' => false,
            ])
            ->addColumn('modified', 'datetime', [
                'default' => null,
                'null' => false,
            ])
            ->create();

        $tagged = $this->table('tags_tagged');
        $tagged->addColumn('tag_id', 'integer', [
                'default' => null,
                'null' => false,
                'signed' => false,
                'length' => 10,
            ])
            ->addColumn('fk_id', 'integer', [
                'default' => null,
                'null' => true,
                'signed' => false,
                'length' => 10,
                'comment' => 'The ID of the entity being tagged'
            ])
            ->addColumn('fk_model', 'string', [
                'default' => null,
                'limit' => 191,
                'null' => false,
                'comment' => 'The model name of the entity being tagged'
            ])
            ->addColumn('created', 'datetime', [
                'default' => null,
                'null' => false,
            ])
            ->addColumn('modified', 'datetime', [
                'default' => null,
                'null' => false,
            ])
            ->create();

        $tags->addIndex(['name'], ['unique' => true])
            ->update();

        $tagged->addIndex(['tag_id', 'fk_id', 'fk_model'], ['unique' => true])
            ->update();
    }
}
