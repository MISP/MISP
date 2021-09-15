<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class UserSettingFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): UserSettingFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'setting' => 'homepage',
            'value' => [
                'path' => '/events/index'
            ],
            'user_id' => (string)$faker->numberBetween(),
            'timestamp' => (string)time()
        ];

        return new UserSettingFixture(array_merge($defaults, $attributes));
    }

    public function toDatabase(): array
    {
        return array_merge(
            parent::toDatabase(),
            [
                'value' => is_array($this->attributes['value']) ? json_encode($this->attributes['value']) : $this->attributes['value']
            ]
        );
    }
}
