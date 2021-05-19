<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class SharingGroupFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): SharingGroupFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'name' => $faker->text(200),
            'releasability' => $faker->text(200),
            'description' => $faker->text(200),
            'uuid' => $faker->uuid,
            'organisation_uuid' => $faker->uuid,
            'org_id' => (string)$faker->numberBetween(),
            'sync_user_id' => (string)$faker->numberBetween(),
            'active' => true,
            'created' => $faker->date('Y-m-d h:i:s', 'now'),
            'modified' => $faker->date('Y-m-d h:i:s', 'now'),
            'local' => true,
            'roaming' => false
        ];

        return new SharingGroupFixture(array_merge($defaults, $attributes));
    }

    public function toSlimResponse(): array
    {
        $response = parent::toResponse();

        unset(
            $response['organisation_uuid'],
            $response['org_id'],
            $response['sync_user_id'],
            $response['created'],
            $response['modified'],
            $response['roaming']
        );

        return $response;
    }
}
