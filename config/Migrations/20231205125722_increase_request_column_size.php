<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class IncreaseRequestColumnSize extends AbstractMigration
{
    public function up()
    {
        $logs = $this->table('access_logs');
        $logs->changeColumn('request', 'blob', ['null' => true, 'default' => 'null']);
        $logs->save();
    }

    public function down()
    {
        $logs = $this->table('access_logs');
        $logs->changeColumn('request', 'varbinary(255)');
        $logs->save();
    }
}
