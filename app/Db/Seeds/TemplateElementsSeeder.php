<?php

declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class TemplateElementsSeeder extends AbstractSeed
{
    public function getDependencies(): array
    {
        return [
            'TemplatesSeeder'
        ];
    }

    public function run(): void
    {
        $data = [
            ['id' => 1, 'template_id' => 1, 'position' => 2, 'element_definition' => 'attribute'],
            ['id' => 2, 'template_id' => 1, 'position' => 3, 'element_definition' => 'attribute'],
            ['id' => 3, 'template_id' => 1, 'position' => 1, 'element_definition' => 'text'],
            ['id' => 4, 'template_id' => 1, 'position' => 4, 'element_definition' => 'attribute'],
            ['id' => 5, 'template_id' => 1, 'position' => 5, 'element_definition' => 'text'],
            ['id' => 6, 'template_id' => 1, 'position' => 6, 'element_definition' => 'attribute'],
            ['id' => 7, 'template_id' => 1, 'position' => 7, 'element_definition' => 'attribute'],
            ['id' => 8, 'template_id' => 1, 'position' => 8, 'element_definition' => 'attribute'],
            ['id' => 11, 'template_id' => 2, 'position' => 1, 'element_definition' => 'text'],
            ['id' => 12, 'template_id' => 2, 'position' => 2, 'element_definition' => 'attribute'],
            ['id' => 13, 'template_id' => 2, 'position' => 3, 'element_definition' => 'text'],
            ['id' => 14, 'template_id' => 2, 'position' => 4, 'element_definition' => 'file'],
            ['id' => 15, 'template_id' => 2, 'position' => 5, 'element_definition' => 'attribute'],
            ['id' => 16, 'template_id' => 2, 'position' => 10, 'element_definition' => 'text'],
            ['id' => 17, 'template_id' => 2, 'position' => 6, 'element_definition' => 'attribute'],
            ['id' => 18, 'template_id' => 2, 'position' => 7, 'element_definition' => 'attribute'],
            ['id' => 19, 'template_id' => 2, 'position' => 8, 'element_definition' => 'attribute'],
            ['id' => 20, 'template_id' => 2, 'position' => 9, 'element_definition' => 'attribute'],
            ['id' => 21, 'template_id' => 2, 'position' => 11, 'element_definition' => 'file'],
            ['id' => 22, 'template_id' => 2, 'position' => 12, 'element_definition' => 'attribute'],
            ['id' => 23, 'template_id' => 2, 'position' => 13, 'element_definition' => 'attribute'],
            ['id' => 24, 'template_id' => 2, 'position' => 14, 'element_definition' => 'attribute'],
            ['id' => 25, 'template_id' => 2, 'position' => 15, 'element_definition' => 'attribute'],
            ['id' => 26, 'template_id' => 2, 'position' => 16, 'element_definition' => 'attribute'],
            ['id' => 27, 'template_id' => 2, 'position' => 17, 'element_definition' => 'attribute'],
            ['id' => 28, 'template_id' => 2, 'position' => 18, 'element_definition' => 'attribute'],
            ['id' => 29, 'template_id' => 3, 'position' => 1, 'element_definition' => 'text'],
            ['id' => 30, 'template_id' => 3, 'position' => 2, 'element_definition' => 'file'],
            ['id' => 31, 'template_id' => 3, 'position' => 4, 'element_definition' => 'text'],
            ['id' => 32, 'template_id' => 3, 'position' => 9, 'element_definition' => 'text'],
            ['id' => 33, 'template_id' => 3, 'position' => 11, 'element_definition' => 'text'],
            ['id' => 34, 'template_id' => 3, 'position' => 10, 'element_definition' => 'attribute'],
            ['id' => 35, 'template_id' => 3, 'position' => 12, 'element_definition' => 'attribute'],
            ['id' => 36, 'template_id' => 3, 'position' => 3, 'element_definition' => 'attribute'],
            ['id' => 37, 'template_id' => 3, 'position' => 5, 'element_definition' => 'attribute'],
            ['id' => 38, 'template_id' => 3, 'position' => 6, 'element_definition' => 'attribute'],
            ['id' => 39, 'template_id' => 3, 'position' => 7, 'element_definition' => 'attribute'],
            ['id' => 40, 'template_id' => 3, 'position' => 8, 'element_definition' => 'file'],
            ['id' => 41, 'template_id' => 3, 'position' => 13, 'element_definition' => 'text'],
            ['id' => 42, 'template_id' => 3, 'position' => 14, 'element_definition' => 'attribute'],
            ['id' => 43, 'template_id' => 3, 'position' => 15, 'element_definition' => 'attribute'],
            ['id' => 44, 'template_id' => 3, 'position' => 16, 'element_definition' => 'attribute'],
            ['id' => 45, 'template_id' => 4, 'position' => 1, 'element_definition' => 'text'],
            ['id' => 46, 'template_id' => 4, 'position' => 2, 'element_definition' => 'attribute'],
            ['id' => 47, 'template_id' => 4, 'position' => 3, 'element_definition' => 'attribute']
        ];


        $templateElements = $this->table('template_elements');
        $templateElements->insert($data)
            ->saveData();
    }
}
