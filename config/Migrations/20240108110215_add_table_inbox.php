<?php

declare(strict_types=1);

use Migrations\AbstractMigration;
use Phinx\Db\Adapter\MysqlAdapter;


final class AddTableInbox extends AbstractMigration
{
    public $autoId = false; // turn off automatic `id` column create. We want it to be `int(10) unsigned`

    public function change(): void
    {
        $this->table('inbox')->drop()->save(); // restart from fresh
        $table = $this->table('inbox', [
            'signed' => false,
            'collation' => 'utf8mb4_unicode_ci',
        ]);
        $table
            ->addColumn('id', 'integer', [
                'autoIncrement' => true,
                'limit' => 10,
                'signed' => false,
            ])
            ->addPrimaryKey(['id'])
            ->addColumn('uuid', 'uuid', [
                'default' => null,
                'null' => false,
            ])
            ->addColumn('scope', 'string', [
                'default' => null,
                'null' => false,
                'limit' => 191,
                'comment' => 'The to model on which the request should be performed onto',
            ])
            ->addColumn('action', 'string', [
                'default' => null,
                'null' => false,
                'limit' => 191,
                'comment' => 'A specific action belonging to the model',
            ])
            ->addColumn('title', 'string', [
                'default' => null,
                'null' => false,
                'limit' => 191,
            ])
            ->addColumn('origin', 'string', [
                'default' => null,
                'null' => false,
                'limit' => 191,
            ])
            ->addColumn('user_id', 'integer', [
                'default' => null,
                'null' => true,
                'length' => null,
            ])
            ->addColumn('message', 'text', [
                'default' => null,
                'null' => true,
            ])
            ->addColumn('data', 'text', [
                'default' => null,
                'null' => true,
                'limit' => MysqlAdapter::TEXT_LONG
            ])
            ->addColumn('severity', 'integer', [
                'null' => false,
                'default' => 0,
                'signed' => false,
                'length' => 10,
            ])
            ->addColumn('created', 'datetime', [
                'default' => null,
                'null' => false,
            ])
            ->addColumn('modified', 'datetime', [
                'default' => null,
                'null' => false,
            ]);

        $table->addForeignKey('user_id', 'users', 'id', ['delete'=> 'CASCADE', 'update'=> 'CASCADE']);

        $table->addIndex(['uuid'], ['unique' => true])
              ->addIndex('scope')
              ->addIndex('action')
              ->addIndex('title')
              ->addIndex('origin')
              ->addIndex('created')
              ->addIndex('modified')
              ->addIndex('user_id')
              ->addIndex('severity');

        $table->create();
    }
}
