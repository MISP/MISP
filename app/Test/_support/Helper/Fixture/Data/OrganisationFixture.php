<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class OrganisationFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): OrganisationFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'name' => $faker->text(20),
            'date_created' => $faker->date('Y-m-d h:i:s', 'now'),
            'date_modified' => $faker->date('Y-m-d h:i:s', 'now'),
            'description' => $faker->text(),
            'type' => 'ADMIN',
            'nationality' => '',
            'sector' => '',
            'created_by' => '0',
            'uuid' => $faker->uuid,
            'contacts' => null,
            'local' => true,
            'restricted_to_domain' => [],
            // 'landingpage' => null
        ];

        return new OrganisationFixture(array_merge($defaults, $attributes));
    }

    public function toDatabase(): array
    {
        $row =  parent::toDatabase();

        return array_merge(
            $row,
            [
                'restricted_to_domain' => json_encode($this->attributes['restricted_to_domain'])
            ]
        );
    }
}
