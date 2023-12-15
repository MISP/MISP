<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class TaxonomyEntriesFixture extends TestFixture
{
    public $connection = 'test';

    public const TAXONOMY_ENTRY_1_ID = 1000;
    public const TAXONOMY_ENTRY_1_VALUE = 'test-taxonomy-entry-1';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::TAXONOMY_ENTRY_1_ID,
                'taxonomy_predicate_id' => TaxonomyPredicatesFixture::TAXONOMY_PREDICATE_1_ID,
                'value' => self::TAXONOMY_ENTRY_1_VALUE,
                'expanded' => 'Test Taxonomy Entry',
                'colour' => '1',
                'description' => 'Text taxonomy predicate',
                'numerical_value' => 1,
            ]
        ];
        parent::init();
    }
}
