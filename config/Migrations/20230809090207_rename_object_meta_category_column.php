<?php

declare(strict_types=1);

namespace App\Config\Migrations;

use Phinx\Migration\AbstractMigration;

final class RenameObjectMetaCategoryColumn extends AbstractMigration
{
    public function up()
    {
        $objectTemplates = $this->table('object_templates');
        $objectTemplates->renameColumn('meta-category', 'meta_category');
        $objectTemplates->save();
        $objects = $this->table('objects');
        $objects->renameColumn('meta-category', 'meta_category');
        $objects->save();
    }

    public function down()
    {
        $objectTemplates = $this->table('object_templates');
        $objectTemplates->renameColumn('meta_category', 'meta-category');
        $objectTemplates->save();
        $objects = $this->table('objects');
        $objects->renameColumn('meta_category', 'meta-category');
        $objects->save();
    }
}
