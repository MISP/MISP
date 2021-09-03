<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;

class ServerFixture extends AbstractFixture implements FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     */
    public static function fake(array $attributes = []): ServerFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(1, 1000),
            'name' => $faker->text(),
            'url' => rtrim($faker->url, "/"),
            'authkey' => $faker->sha1,
            'org_id' => (string)$faker->numberBetween(1, 1000),
            'push' => false,
            'pull' => false,
            'push_sightings' => false,
            'push_galaxy_clusters' => false,
            'pull_galaxy_clusters' => false,
            'lastpulledid' => null,
            'lastpushedid' => null,
            'organization' => null,
            'remote_org_id' => (string)$faker->numberBetween(1, 1000),
            'publish_without_email' => false,
            'unpublish_event' => false,
            'self_signed' => false,
            'pull_rules' => '{"tags":{"OR":[],"NOT":[]},"orgs":{"OR":[],"NOT":[]},"url_params":""}',
            'push_rules' => '{"tags":{"OR":[],"NOT":[]},"orgs":{"OR":[],"NOT":[]}}',
            'cert_file' => null,
            'client_cert_file' => null,
            'internal' => false,
            'skip_proxy' => false,
            'caching_enabled' => false,
            'priority' => '1'
        ];

        return new ServerFixture(array_merge($defaults, $attributes));
    }

    public function toRequest(): array
    {
        $request = parent::toRequest();
        unset($request['id']);

        return $request;
    }

    public function toResponse(): array
    {
        $request = parent::toResponse();
        unset($request['authkey']);

        return $request;
    }
}
