<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class RenameChangeColumnNoticelists extends AbstractMigration
{
    public function up()
    {
        $logs = $this->table('logs');
        $logs->renameColumn('change', 'changes');
        $logs->save();
    }

    public function down()
    {
        $logs = $this->table('logs');
        $logs->renameColumn('changes', 'change');
        $logs->save();
    }
}
