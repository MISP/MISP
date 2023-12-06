<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class RenameChangeColumnAuditlogs extends AbstractMigration
{
    public function up()
    {
        $logs = $this->table('audit_logs');
        $logs->changeColumn('change', 'blob');
        $logs->save();
        $logs = $this->table('audit_logs');
        $logs->renameColumn('change', 'changed');
        $logs->save();
    }

    public function down()
    {
        $logs = $this->table('audit_logs');
        $logs->changeColumn('changed', 'binary');
        $logs->save();
        $logs = $this->table('audit_logs');
        $logs->renameColumn('changed', 'change');
        $logs->save();
    }
}
