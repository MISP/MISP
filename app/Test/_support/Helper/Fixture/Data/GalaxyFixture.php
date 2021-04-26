<?php

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class GalaxyFixture extends AbstractFixture implements FixtureInterface
{
    public static function fake(array $attributes = []): GalaxyFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(1, 1000),
            'uuid' => $faker->uuid,
            'name' => $faker->text(),
            'type' => $faker->randomElement(['tool', 'android', 'botnet']),
            'description' => $faker->text(),
            'version' => '1',
            'icon' => $faker->randomElement(['globe', 'eye', 'shield', 'btc']),
            'namespace' => $faker->randomElement(['misp', 'mitre-attack']),
        ];

        return new GalaxyFixture(array_merge($defaults, $attributes));
    }
}
