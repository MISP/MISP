<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class TaxonomiesFixture extends TestFixture
{
    public $connection = 'test';

    public const TAXONOMY_1_ID = 1000;
    public const TAXONOMY_1_NAMESPACE = 'test-taxonomy-1';

    public const TAXONOMY_2_ID = 2000;
    public const TAXONOMY_2_NAMESPACE = 'test-taxonomy-2';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::TAXONOMY_1_ID,
                'namespace' => self::TAXONOMY_1_NAMESPACE,
                'description' => 'Test Taxonomy 1',
                'version' => '1',
                'enabled' => true,
                'exclusive' => false,
                'required' => false,
                'highlighted' => false,
            ],
            [
                'id' => self::TAXONOMY_2_ID,
                'namespace' => self::TAXONOMY_2_NAMESPACE,
                'description' => 'Test Taxonomy 2',
                'version' => '1',
                'enabled' => false,
                'exclusive' => false,
                'required' => false,
                'highlighted' => false,
            ]
        ];
        parent::init();
    }
}
