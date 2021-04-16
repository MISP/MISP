<?php

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class AuthKeyFixture extends AbstractFixture implements FixtureInterface
{
    public static function fake(array $attributes = []): AuthKeyFixture
    {
        $faker = \Faker\Factory::create();

        $authkey = $attributes['authkey'] ?? $faker->sha1;

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'uuid' => $faker->uuid,
            'authkey' => $authkey,
            'authkey_start' => substr($authkey, 0, 4),
            'authkey_end' => substr($authkey, 36, 40),
            'created' => 1617286581,
            'expiration' => 0,
            'user_id' => 1,
            'comment' => ''
        ];

        return new AuthKeyFixture(array_merge($defaults, $attributes));
    }

    public function toDatabase(): array
    {
        return array_merge(
            parent::toDatabase(),
            [
                'authkey' => password_hash($this->attributes['authkey'],  PASSWORD_BCRYPT)
            ]
        );
    }
}
