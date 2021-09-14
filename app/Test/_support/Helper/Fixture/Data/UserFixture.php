<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class UserFixture extends AbstractFixture implements FixtureInterface
{
    public const ROLE_ADMIN = 1;
    public const ROLE_ORG_ADMIN = 2;
    public const ROLE_USER = 3;
    public const ROLE_PUBLISHER = 4;
    public const ROLE_SYNC_USER = 5;
    public const ROLE_READ_ONLY = 6;

    /** @var string|boolean */
    private $passwordHash;

    /**
     * @param array<mixed> $attributes
     * @param string $passwordHash
     */
    public function __construct(array $attributes, string $passwordHash)
    {
        $this->passwordHash = $passwordHash;
        parent::__construct($attributes);
    }

    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): UserFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'password' => $faker->password(12),
            'org_id' => (string)$faker->numberBetween(),
            'server_id' => (string)$faker->numberBetween(),
            'email' => $faker->email,
            'autoalert' => false,
            'authkey' => $faker->sha1,
            'invited_by' => '0',
            'gpgkey' => '',
            'certif_public' => '',
            'nids_sid' => '4000000',
            'termsaccepted' => true,
            'newsread' => '0',
            'role_id' => '1',
            'change_pw' => '0',
            'contactalert' => false,
            'disabled' => false,
            'expiration' => null,
            'current_login' => '0',
            'last_login' => '0',
            'force_logout' => false,
            'date_created' => (string)time(),
            'date_modified' => (string)time()
        ];

        $attributes = array_merge($defaults, $attributes);
        $passwordHash = (string)password_hash($attributes['password'],  PASSWORD_BCRYPT);

        return new UserFixture($attributes, $passwordHash);
    }

    public function toRequest(): array
    {
        $request = parent::toRequest();
        unset($request['password']);

        return $request;
    }

    public function toDatabase(): array
    {
        return array_merge(
            parent::toDatabase(),
            [
                'password' => $this->passwordHash
            ]
        );
    }

    public function toResponse(): array
    {
        $response = parent::toResponse();
        unset($response['password']);
        unset($response['authkey']);

        return $response;
    }

    public function getAuthKey(): string
    {
        return $this->attributes['authkey'];
    }
}
