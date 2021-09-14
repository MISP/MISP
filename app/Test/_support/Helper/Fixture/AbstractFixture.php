<?php

declare(strict_types=1);

namespace Helper\Fixture;

abstract class AbstractFixture
{

    /** @var array<mixed> */
    protected $attributes;

    /**
     * @param array<mixed> $attributes
     */
    public function __construct(array $attributes)
    {
        $this->attributes = $attributes;
    }

    /**
     * Updates the fixture with the given attributes
     * 
     * @param array<mixed> $attributes
     * 
     * @return void
     */
    public function set(array $attributes): void
    {
        $this->attributes = array_merge($this->attributes, $attributes);
    }

    /**
     * Returns the API request representation of the entity mocked by this fixture
     * 
     * @return array<mixed>
     */
    public function toRequest(): array
    {
        return $this->attributes;
    }

    /**
     * Returns the API response representation of the entity mocked by this fixture
     * 
     * @return array<mixed>
     */
    public function toResponse(): array
    {
        return $this->attributes;
    }

    /**
     * Returns the database representation of the entity mocked by this fixture
     * 
     * @return array<mixed>
     */
    public function toDatabase(): array
    {
        return $this->attributes;
    }
}
