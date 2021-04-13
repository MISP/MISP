<?php

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class UserFixture extends AbstractFixture implements FixtureInterface
{
    public static function fake(array $attributes = []): UserFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => $faker->numberBetween(),
            'password' => $faker->password(10),
            'org_id' => $faker->numberBetween(),
            'server_id' => $faker->numberBetween(),
            'email' => $faker->email,
            'autoalert' => 0,
            'authkey' => $faker->sha1,
            'invited_by' => 0,
            'gpgkey' => null,
            'certif_public' => '',
            'nids_sid' => 4000000,
            'termsaccepted' => 1,
            'newsread' => 1,
            'role_id' => 1,
            'change_pw' => 0,
            'contactalert' => 0,
            'disabled' => 0,
            'expiration' => null,
            'current_login' => 0,
            'last_login' => 0,
            'force_logout' => 0,
            'date_created' => time(),
            'date_modified' => time()
        ];

        return new UserFixture(array_merge($defaults, $attributes));
    }

    public function toDatabase(): array
    {
        return array_merge(
            parent::toDatabase(),
            [
                'password' => password_hash($this->attributes['password'],  PASSWORD_BCRYPT)
            ]
        );
    }
}
