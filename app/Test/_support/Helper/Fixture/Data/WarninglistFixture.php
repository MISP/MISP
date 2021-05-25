<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class WarninglistFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): WarninglistFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'name' => $faker->text(200),
            'type' => 'cidr',
            'description' => $faker->text(200),
            'version' => (string)$faker->numberBetween(),
            'enabled' => false,
            'warninglist_entry_count' => (string)$faker->numberBetween()
        ];

        return new WarninglistFixture(array_merge($defaults, $attributes));
    }
}
