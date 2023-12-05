<?php

declare(strict_types=1);

namespace App\Config\Migrations;

use Phinx\Migration\AbstractMigration;

final class RenameObjectElementUiPriorityColumn extends AbstractMigration
{
    public function up()
    {
        $objectTemplateElements = $this->table('object_template_elements');
        $objectTemplateElements->renameColumn('ui-priority', 'ui_priority');
        $objectTemplateElements->save();
    }

    public function down()
    {
        $objectTemplateElements = $this->table('object_template_elements');
        $objectTemplateElements->renameColumn('ui_priority', 'ui-priority');
        $objectTemplateElements->save();
    }
}
