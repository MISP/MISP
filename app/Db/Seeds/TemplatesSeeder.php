<?php

declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class TemplatesSeeder extends AbstractSeed
{
    public function shouldExecute(): bool
    {
        $templates = $this->hasTable('templates');

        print_r($templates);

        return true;
    }

    public function run(): void
    {
        $data = [
            [
                'id' => 1,
                'name' => 'Phishing E-mail',
                'description' => 'Create a MISP event about a Phishing E-mail.',
                'org' => 'MISP',
                'share' => 1
            ],
            [
                'id' => 2,
                'name' => 'Phishing E-mail with malicious attachment',
                'description' => 'A MISP event based on Spear-phishing containing a malicious attachment. This event can include anything from the description of the e-mail itself, the malicious attachment and its description as well as the results of the analysis done on the malicious f',
                'org' => 'MISP',
                'share' => 1
            ],
            [
                'id' => 3,
                'name' => 'Malware Report',
                'description' => 'This is a template for a generic malware report.',
                'org' => 'MISP',
                'share' => 1
            ],
            [
                'id' => 4,
                'name' => 'Indicator List',
                'description' => 'A simple template for indicator lists.',
                'org' => 'MISP',
                'share' => 1
            ]
        ];

        $templates = $this->table('templates');
        $templates->insert($data)
            ->saveData();
    }
}
