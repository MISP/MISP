<?php

declare(strict_types=1);

namespace Helper\Fixture\Data;

use \Helper\Fixture\AbstractFixture;
use \Helper\Fixture\FixtureInterface;
use \Helper\Fixture\TaxonomyPredicateFixture;

class TaxonomyFixture extends AbstractFixture implements FixtureInterface
{
    /** @var TaxonomyPredicateFixture[]  */
    private $predicates;

    /**
     * @param array<mixed> $attributes
     * @param array<TaxonomyPredicateFixture> $predicates
     */
    public function __construct(array $attributes = [], array $predicates = [])
    {
        $this->predicates = $predicates;
        parent::__construct($attributes);
    }

    /**
     * @param array<mixed> $attributes
     * @param array<TaxonomyPredicateFixture> $predicates
     */
    public static function fake(array $attributes = [], array $predicates = []): TaxonomyFixture
    {
        $faker = \Faker\Factory::create();

        $defaults = [
            'id' => (string)$faker->numberBetween(),
            'namespace' => $faker->sha256,
            'description' => $faker->text(200),
            'version' => $faker->numberBetween(1, 10),
            'enabled' => false,
            'exclusive' => false,
            'required' => false,
        ];

        return new TaxonomyFixture(array_merge($defaults, $attributes), $predicates);
    }

    /**
     * @return array<mixed>
     */
    public function toExportResponse(): array
    {
        $response = [
            'namespace' => $this->attributes['namespace'],
            'description' => $this->attributes['description'],
            'exclusive' => $this->attributes['exclusive'],
            'version' => $this->attributes['version']
        ];

        if (!empty($this->predicates)) {
            $response['predicates'] = array_map(
                function ($predicate) {
                    return $predicate->toExportResponse();
                },
                $this->predicates
            );
        }

        return $response;
    }
}
