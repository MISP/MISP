<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class TaxonomyPredicateFixture extends AbstractFixture implements FixtureInterface
{
    /** @var TaxonomyEntryFixture[]  */
    private $entries;

    /**
     * @param array<mixed> $attributes
     * @param array<TaxonomyEntryFixture> $entries
     */
    public function __construct(array $attributes = [], array $entries = [])
    {
        $this->entries = $entries;
        parent::__construct($attributes);
    }

    /**
     * @param array<mixed> $attributes
     * @param array<TaxonomyEntryFixture> $entries
     */
    public static function fake(array $attributes = [], $entries = []): TaxonomyPredicateFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'taxonomy_id' => (string)$faker->numberBetween(),
            'value' => $faker->sha256,
            'expanded' => $faker->text(200),
            'colour' => null,
            'description' => null,
            'exclusive' => 0,
            'numerical_value' => null,
        ];

        return new TaxonomyPredicateFixture(array_merge($defaults, $attributes), $entries);
    }
    /**
     * @return array<mixed>
     */
    public function toExportResponse(): array
    {
        return [
            'value' => $this->attributes['value'],
            'expanded' => $this->attributes['expanded'],
        ];
    }
}
