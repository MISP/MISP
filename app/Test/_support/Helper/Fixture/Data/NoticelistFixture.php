<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class NoticelistFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): NoticelistFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'name' => $faker->text(20),
            'expanded_name' => $faker->text(200),
            'ref' => '[]',
            'geographical_area' => '[]',
            'version' => (string)$faker->numberBetween(),
            'enabled' => false
        ];

        return new NoticelistFixture(array_merge($defaults, $attributes));
    }

    public function toResponse(): array
    {
        $response =  parent::toResponse();

        return array_merge(
            $response,
            [
                'ref' => json_decode($this->attributes['ref']),
                'geographical_area' => json_decode($this->attributes['geographical_area'])
            ]
        );
    }
}
