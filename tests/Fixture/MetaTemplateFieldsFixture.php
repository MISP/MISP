<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class MetaTemplateFieldsFixture extends TestFixture
{
    public $connection = 'test';

    public function init(): void
    {
        $this->records = [
            [
                'field' => 'test_field_1',
                'type' => 'text',
                'meta_template_id' => MetaTemplatesFixture::ENABLED_TEST_ORG_META_TEMPLATE_ID,
                'regex' => null,
                'multiple' => 1,
                'enabled' => 1,
                'counter' => 0
            ]
        ];

        parent::init();
    }
}
