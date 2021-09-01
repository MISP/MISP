<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class LogFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): LogFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => $faker->numberBetween(),
            'title' => $faker->text(20),
            'created' => $faker->date('Y-m-d H:i:s', 'now'),
            'model' => $faker->randomElement(['Attribute', 'AuthKey', 'Feed']),
            'model_id' => $faker->numberBetween(),
            'action' =>  $faker->randomElement(['add', 'edit', 'delete']),
            'user_id' => $faker->numberBetween(),
            'change' => $faker->text(100),
            'email' => $faker->email,
            'org' => $faker->text(10),
            'description' => $faker->text(100),
            'ip' => $faker->ipv4,
        ];

        return new LogFixture(array_merge($defaults, $attributes));
    }
}
