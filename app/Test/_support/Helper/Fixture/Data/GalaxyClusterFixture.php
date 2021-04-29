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
            'tag_name' => '',
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

    public function toRequest(): array
    {
        $request =  parent::toRequest();
        unset($request['tag_name']);

        return array_merge(
            $request,
            [
                'authors' => json_decode($this->attributes['authors'])
            ]
        );
    }

    public function toResponse(): array
    {
        $response = array_merge(
            parent::toResponse(),
            [
                'authors' => json_decode($this->attributes['authors'])
            ]
        );

        if (!empty($this->galaxyElements)) {
            $response['GalaxyElement'] = array_map(
                function ($galaxyElement) {
                    return $galaxyElement->toResponse();
                },
                $this->galaxyElements
            );
        }

        return $response;
    }

    public function toExportResponse(): array
    {
        $response = $this->toResponse();
        unset($response['id'], $response['galaxy_id']);

        if (isset($response['GalaxyElement'])) {
            foreach ($response['GalaxyElement'] as &$galaxyElement) {
                unset($galaxyElement['id'], $galaxyElement['galaxy_cluster_id']);
            }
        }

        return $response;
    }
}
