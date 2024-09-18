<?php

declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class AdminSettingsSeeder extends AbstractSeed
{
    public function run(): void
    {
        $data = [
            [
                'id'    => 1,
                'setting' => 'db_version',
                'value' => '129'
            ],
            [
                'id'    => 2,
                'setting' => 'fix_login',
                'value' => date('Y-m-d H:i:s')
            ],
            [
                'id'    => 3,
                'setting' => 'default_role',
                'value' => '3'
            ]
        ];

        $adminSettings = $this->table('admin_settings');
        $adminSettings->insert($data)
            ->saveData();
    }
}
