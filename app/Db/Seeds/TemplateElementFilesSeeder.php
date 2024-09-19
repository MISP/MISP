<?php

declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class TemplateElementFilesSeeder extends AbstractSeed
{
    public function getDependencies(): array
    {
        return [
            'TemplatesSeeder',
            'TemplateElementsSeeder'
        ];
    }

    public function run(): void
    {
        $data = [
            ['id' => 1, 'template_element_id' => 14, 'name' => 'Malicious Attachment', 'description' => 'The file (or files) that was (were) attached to the e-mail itself.', 'category' => 'Payload delivery', 'malware' => 1, 'mandatory' => 0, 'batch' => 1],
            ['id' => 2, 'template_element_id' => 21, 'name' => 'Payload installation', 'description' => 'Payload installation detected during the analysis', 'category' => 'Payload installation', 'malware' => 1, 'mandatory' => 0, 'batch' => 1],
            ['id' => 3, 'template_element_id' => 30, 'name' => 'Malware sample', 'description' => 'The sample that the report is based on', 'category' => 'Payload delivery', 'malware' => 1, 'mandatory' => 0, 'batch' => 0],
            ['id' => 4, 'template_element_id' => 40, 'name' => 'Artifacts dropped (Sample)', 'description' => 'Upload any files that were dropped during the analysis.', 'category' => 'Artifacts dropped', 'malware' => 1, 'mandatory' => 0, 'batch' => 1],
        ];

        $tempalteElementFiles = $this->table('template_element_files');
        $tempalteElementFiles->insert($data)
            ->saveData();
    }
}
