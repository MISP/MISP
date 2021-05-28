<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;
use \Helper\Fixture\Data\AttributeFixture;

class ObjectFixture extends AbstractFixture implements FixtureInterface
{
    /** @var AttributeFixture[]  */
    private $objectAttributes;

    /**
     * @param array<mixed> $attributes
     * @param array<AttributeFixture> $objectAttributes
     */
    public function __construct(array $attributes, array $objectAttributes)
    {
        $this->objectAttributes = $objectAttributes;
        parent::__construct($attributes);
    }

    /**
     * @param array<mixed> $attributes
     * @param array<AttributeFixture> $objectAttributes
     */
    public static function fake(array $attributes = [], array $objectAttributes = []): ObjectFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'name' => $faker->text(200),
            'meta-category' => 'misc',
            'description' => $faker->text(200),
            'template_uuid' => $faker->uuid,
            'template_version' => (string)$faker->numberBetween(),
            'event_id' => (string)$faker->numberBetween(),
            'uuid' => $faker->uuid,
            'timestamp' => (string)time(),
            'distribution' => '0',
            'sharing_group_id' => '0',
            'comment' => '',
            'deleted' => false,
            'first_seen' => null,
            'last_seen' => null
        ];

        return new ObjectFixture(array_merge($defaults, $attributes), $objectAttributes);
    }

    public function toResponse(): array
    {
        $response = parent::toResponse();

        if (!empty($this->objectAttributes)) {
            $response['Attribute'] = array_map(
                function ($attribute) {
                    return $attribute->toResponse();
                },
                $this->objectAttributes
            );
        }

        return $response;
    }
}
