<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class RenameChangeColumnLogs extends AbstractMigration
{
    public function up()
    {
        $logs = $this->table('logs');
        $logs->renameColumn('change', 'changed');
        $logs->save();
    }

    public function down()
    {
        $logs = $this->table('logs');
        $logs->renameColumn('changed', 'change');
        $logs->save();
    }
}
