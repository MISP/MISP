<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class FeedFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): FeedFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'name' => $faker->text(200),
            'provider' => $faker->text(200),
            'url' => $faker->url,
            'rules' => null,
            'enabled' => true,
            'distribution' => '3',
            'sharing_group_id' => '0',
            'tag_id' => '0',
            'default' => false,
            'source_format' => '1',
            'fixed_event' => false,
            'delta_merge' => false,
            'event_id' => '0',
            'publish' => false,
            'override_ids' => false,
            'settings' => '[]',
            'input_source' => 'network',
            'delete_local_file' => false,
            'lookup_visible' => false,
            'headers' => null,
            'caching_enabled' => false,
            'force_to_ids' => false,
            'orgc_id' => (string)$faker->numberBetween()
        ];

        return new FeedFixture(array_merge($defaults, $attributes));
    }

    public function toRequest(): array
    {
        $request = parent::toRequest();
        unset($request['settings']);

        return $request;
    }
}
