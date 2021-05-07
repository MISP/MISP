<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class AttributeFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): AttributeFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(1, 1000),
            'event_id' => (string)$faker->numberBetween(1, 1000),
            'object_id' => '0',
            'object_relation' => null,
            'category' => 'Other',
            'type' => 'text',
            'value1' => $faker->randomAscii,
            'value2' => '',
            'to_ids' => true,
            'uuid' => $faker->uuid,
            'timestamp' => '0',
            'distribution' => '0',
            'sharing_group_id' => '0',
            'comment' => $faker->text(200),
            'deleted' => false,
            'disable_correlation' => false,
            'first_seen' => null,
            'last_seen' => null
        ];

        return new AttributeFixture(array_merge($defaults, $attributes));
    }

    public function toRequest(): array
    {
        return [
            'id' => $this->attributes['id'],
            'event_id' => $this->attributes['event_id'],
            'object_id' => $this->attributes['object_id'],
            'object_relation' => $this->attributes['object_relation'],
            'category' => $this->attributes['category'],
            'type' => $this->attributes['type'],
            'value' => $this->attributes['value1'],
            'to_ids' => $this->attributes['to_ids'],
            'uuid' => $this->attributes['uuid'],
            'timestamp' => $this->attributes['timestamp'],
            'distribution' => $this->attributes['distribution'],
            'sharing_group_id' => $this->attributes['sharing_group_id'],
            'comment' => $this->attributes['comment'],
            'deleted' => $this->attributes['deleted'],
            'disable_correlation' => $this->attributes['disable_correlation'],
            'first_seen' => $this->attributes['first_seen'],
            'last_seen' => $this->attributes['last_seen']
        ];
    }

    public function toResponse(): array
    {
        return [
            'id' => $this->attributes['id'],
            'event_id' => $this->attributes['event_id'],
            'object_id' => $this->attributes['object_id'],
            'object_relation' => $this->attributes['object_relation'],
            'category' => $this->attributes['category'],
            'type' => $this->attributes['type'],
            'value' => $this->attributes['value1'],
            'to_ids' => $this->attributes['to_ids'],
            'uuid' => $this->attributes['uuid'],
            'timestamp' => $this->attributes['timestamp'],
            'distribution' => $this->attributes['distribution'],
            'sharing_group_id' => $this->attributes['sharing_group_id'],
            'comment' => $this->attributes['comment'],
            'deleted' => $this->attributes['deleted'],
            'disable_correlation' => $this->attributes['disable_correlation'],
            'first_seen' => $this->attributes['first_seen'],
            'last_seen' => $this->attributes['last_seen']
        ];
    }
}
