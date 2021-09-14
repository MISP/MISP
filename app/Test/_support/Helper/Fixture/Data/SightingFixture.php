<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class SightingFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): SightingFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'attribute_id' => (string)$faker->numberBetween(),
            'event_id' => (string)$faker->numberBetween(),
            'org_id' => (string)$faker->numberBetween(),
            'date_sighting' => (string)time(),
            'uuid' => $faker->uuid,
            'source' => '',
            'type' => '0'
        ];

        return new SightingFixture(array_merge($defaults, $attributes));
    }
}
