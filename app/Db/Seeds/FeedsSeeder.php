<?php

declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class FeedsSeeder extends AbstractSeed
{
    public function run(): void
    {
        $data = [
            [
                'id'    => 1,
                'provider' => 'CIRCL',
                'name' => 'CIRCL OSINT Feed',
                'url' => 'https://www.circl.lu/doc/misp/feed-osint',
                'distribution' => 3,
                'default' => 1,
                'enabled' => 0,
            ],
            [
                'id'    => 2,
                'provider' => 'Botvrij.eu',
                'name' => 'The Botvrij.eu Data',
                'url' => 'https://www.botvrij.eu/data/feed-osint',
                'distribution' => 3,
                'default' => 1,
                'enabled' => 0,
            ]
        ];

        $feeds = $this->table('feeds');
        $feeds->insert($data)
            ->saveData();
    }
}
