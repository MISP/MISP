<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class TagFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): TagFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'name' => $faker->text(200),
            'colour' => '#ffffff',
            'exportable' => true,
            'org_id' => (string)$faker->numberBetween(),
            'user_id' => (string)$faker->numberBetween(),
            'hide_tag' => false,
            'numerical_value' => null,
        ];

        return new TagFixture(array_merge($defaults, $attributes));
    }
}
