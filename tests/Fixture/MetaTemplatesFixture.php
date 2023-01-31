<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class MetaTemplatesFixture extends TestFixture
{
    public $connection = 'test';

    public const ENABLED_TEST_ORG_META_TEMPLATE_ID = 1;
    public const ENABLED_TEST_ORG_META_TEMPLATE_UUID = 'ee26022a-69e2-4451-bfda-f2ca9f3dd2e5';
    public const DISABLED_TEST_ORG_META_TEMPLATE_ID = 2;
    public const DISABLED_TEST_ORG_META_TEMPLATE_UUID = '698c616d-49f3-4c51-9364-6e223ff4bbc2';

    public const ENABLED_TEST_ORG_META_TEMPLATE_SPEC = [
        'uuid' => self::ENABLED_TEST_ORG_META_TEMPLATE_UUID,
        'name' => 'Test Org Meta Template (enabled)',
        'description' => 'Test Org Meta Template Description (enabled)',
        'version' => 2,
        'scope' => 'organisation',
        'namespace' => 'test',
        'source' => 'Cerebrate',
        'metaFields' => [
            [
                "field" => "test_field_1",
                "type" => "text",
                "multiple" => true
            ],
            [
                "field" => "test_field_2",
                "type" => "text",
                "multiple" => true
            ]
        ],
    ];

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::ENABLED_TEST_ORG_META_TEMPLATE_ID,
                'scope' => 'organisation',
                'name' => 'Test Meta Template (enabled)',
                'namespace' => 'cerebrate',
                'description' => 'Test Meta Template Description (enabled)',
                'version' => '1',
                'uuid' => self::ENABLED_TEST_ORG_META_TEMPLATE_UUID,
                'source' => 'Cerebrate',
                'enabled' => true,
                'is_default' => false,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::DISABLED_TEST_ORG_META_TEMPLATE_ID,
                'scope' => 'organisation',
                'name' => 'Test Meta Template (disabled)',
                'namespace' => 'cerebrate',
                'description' => 'Test Meta Template Description (disabled)',
                'version' => '1',
                'uuid' => self::DISABLED_TEST_ORG_META_TEMPLATE_UUID,
                'source' => 'Cerebrate',
                'enabled' => false,
                'is_default' => false,
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ]
        ];

        parent::init();
    }
}
