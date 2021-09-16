<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class TaxonomyEntryFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): TaxonomyEntryFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'taxonomy_predicate_id' => (string)$faker->numberBetween(),
            'value' => $faker->sha256,
            'expanded' => $faker->text(200),
            'colour' => null,
            'description' => null,
            'numerical_value' => null,
        ];

        return new TaxonomyEntryFixture(array_merge($defaults, $attributes));
    }
}
