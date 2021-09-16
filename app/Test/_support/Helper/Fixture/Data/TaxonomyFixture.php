<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class TaxonomyFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): TaxonomyFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'namespace' => $faker->sha256,
            'description' => $faker->text(200),
            'version' => (string)$faker->numberBetween(1, 10),
            'enabled' => false,
            'exclusive' => false,
            'required' => false,
        ];

        return new TaxonomyFixture(array_merge($defaults, $attributes));
    }
}
