<?php

declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class OrgBlocklistsSeeder extends AbstractSeed
{
    public function run(): void
    {
        $data = [
            ['org_uuid' => '58d38339-7b24-4386-b4b4-4c0f950d210f', 'created' => 'NOW()', 'org_name' => 'Setec Astrononomy', 'comment' => 'default example'],
            ['org_uuid' => '58d38326-eda8-443a-9fa8-4e12950d210f', 'created' => 'NOW()', 'org_name' => 'Acme Finance', 'comment' => 'default example'],
        ];

        $orgBlocklists = $this->table('org_blocklists');
        $orgBlocklists->insert($data)
            ->saveData();
    }
}
