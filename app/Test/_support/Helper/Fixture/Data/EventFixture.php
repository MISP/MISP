<?php

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class EventFixture extends AbstractFixture implements FixtureInterface
{
    public static function fake(array $attributes = []): EventFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(1, 1000),
            'org_id' => (string)$faker->numberBetween(1, 1000),
            'date' => $faker->date('Y-m-d'),
            'info' => $faker->text(200),
            'user_id' => 1,
            'uuid' => $faker->uuid,
            'published' => false,
            'analysis' => '0',
            'attribute_count' => '0',
            'orgc_id' => '1',
            'timestamp' => '0',
            'distribution' => '0',
            'sharing_group_id' => '1',
            'proposal_email_lock' => '1',
            'threat_level_id' => '0',
            'publish_timestamp' => '0',
            'sighting_timestamp' => '0',
            'disable_correlation' => false,
            'extends_uuid' => $faker->uuid,
        ];

        return new EventFixture(array_merge($defaults, $attributes));
    }

    public function toResponse(): array
    {
        return [
            'id' => $this->attributes['id'],
            'org_id' => $this->attributes['org_id'],
            'date' => $this->attributes['date'],
            'info' => $this->attributes['info'],
            'user_id' => $this->attributes['user_id'],
            'uuid' => $this->attributes['uuid'],
            'published' => $this->attributes['published'],
            'analysis' => $this->attributes['analysis'],
            'attribute_count' => $this->attributes['attribute_count'],
            'orgc_id' => $this->attributes['orgc_id'],
            'timestamp' => $this->attributes['timestamp'],
            'distribution' => $this->attributes['distribution'],
            'sharing_group_id' => $this->attributes['sharing_group_id'],
            'proposal_email_lock' => $this->attributes['proposal_email_lock'],
            'threat_level_id' => $this->attributes['threat_level_id'],
            'publish_timestamp' => $this->attributes['publish_timestamp'],
            'sighting_timestamp' => $this->attributes['sighting_timestamp'],
            'disable_correlation' => $this->attributes['disable_correlation'],
            'extends_uuid' => $this->attributes['extends_uuid']
        ];
    }
}
