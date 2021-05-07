<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class GalaxyElementFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): GalaxyElementFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(1, 1000),
            'galaxy_cluster_id' => (string)$faker->numberBetween(1, 1000),
            'key' => $faker->randomElement(['categories', 'address', 'topics']),
            'value' => $faker->text(),
        ];

        return new GalaxyElementFixture(array_merge($defaults, $attributes));
    }
}
