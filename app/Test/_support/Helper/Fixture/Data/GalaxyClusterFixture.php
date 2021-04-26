<?php

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class GalaxyClusterFixture extends AbstractFixture implements FixtureInterface
{
    /** @var GalaxyElementFixture[]  */
    private $galaxyElements;

    public function __construct(array $attributes, $galaxyElements)
    {
        $this->galaxyElements = $galaxyElements;
        parent::__construct($attributes);
    }

    public static function fake(array $attributes = [], array $galaxyElements = []): GalaxyClusterFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(1, 1000),
            'uuid' => $faker->uuid,
            'collection_uuid' => $faker->uuid,
            'type' => $faker->randomElement(['tool', 'android', 'botnet']),
            'value' => $faker->text(),
            'tag_name' => $faker->randomElement(
                [
                    'misp-galaxy:sod-matrix="Ensuring that fundamental rights are respected during the investigation and prosecution - CSIRT - [S]"',
                    'misp-galaxy:mitre-enterprise-attack-attack-pattern="Signed Binary Proxy Execution - T1218"'
                ]
            ),
            'description' => $faker->text(),
            'galaxy_id' => (string)$faker->numberBetween(1, 1000),
            'source' => 'https://github.com/mitre/cti',
            'authors' => '["MITRE"]',
            'version' => '1',
            'distribution' => '1',
            'sharing_group_id' => null,
            'org_id' => '0',
            'orgc_id' => '0',
            'default' => true,
            'locked' => false,
            'extends_uuid' => '',
            'extends_version' => '0',
            'published' => false,
            'deleted' => false,
        ];

        return new GalaxyClusterFixture(array_merge($defaults, $attributes), $galaxyElements);
    }

    public function toResponse(): array
    {
        return array_merge(
            parent::toResponse(),
            [
                'authors' => json_decode($this->attributes['authors']),
                'GalaxyElement' => array_map(
                    function ($galaxyElement) {
                        return $galaxyElement->toResponse();
                    },
                    $this->galaxyElements
                )
            ]
        );
    }
}
