<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class ObjectTemplateElementsFixture extends TestFixture
{
    public $connection = 'test';

    public const OBJECT_TEMPLATE_ELEMENT_1_ID = 1;

    public function init(): void
    {
        $this->records = [
            [
                'id' => self::OBJECT_TEMPLATE_ELEMENT_1_ID,
                'object_template_id' => ObjectTemplatesFixture::OBJECT_TEMPLATE_1_ID,
                'object_relation' => 'test',
                'type' => '',
                'ui_priority' => 1,
                'categories' => json_encode(['test']),
                'values_list' => json_encode(['test']),
                'sane_default' => json_encode(['test']),
                'description' => 'test description',
                'disable_correlation' => 0,
                'multiple' => 0
            ]
        ];
        parent::init();
    }
}
