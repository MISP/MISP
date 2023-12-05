<?php
declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class IncreaseQueryLogColumnSize extends AbstractMigration
{
    public function up()
    {
        $logs = $this->table('access_logs');
        $logs->changeColumn('query_log', 'blob');
        $logs->save();
    }

    public function down()
    {
        $logs = $this->table('access_logs');
        $logs->changeColumn('query_log', 'varbinary(255)');
        $logs->save();
    }
}
