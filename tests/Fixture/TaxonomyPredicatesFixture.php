<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class TaxonomyPredicatesFixture extends TestFixture
{
    public $connection = 'test';

    public const TAXONOMY_PREDICATE_1_ID = 1000;
    public const TAXONOMY_PREDICATE_1_VALUE = 'test-taxonomy-predicate-1';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::TAXONOMY_PREDICATE_1_ID,
                'taxonomy_id' => TaxonomiesFixture::TAXONOMY_1_ID,
                'value' => self::TAXONOMY_PREDICATE_1_VALUE,
                'expanded' => 'Test Taxonomy Predicate',
                'colour' => '1',
                'description' => 'Text taxonomy predicate',
                'exclusive' => false,
                'numerical_value' => 1,
            ]
        ];
        parent::init();
    }
}
