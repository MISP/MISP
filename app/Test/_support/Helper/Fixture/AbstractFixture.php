<?php

namespace Helper\Fixture;

abstract class AbstractFixture
{

    /** @var array */
    protected $attributes;

    public function __construct(array $attributes)
    {
        $this->attributes = $attributes;
    }

    /**
     * Updates the fixture with the given attributes
     * 
     * @param array $attributes
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
     * @return array
     */
    public function toRequest(): array
    {
        return $this->attributes;
    }

    /**
     * Returns the API response representation of the entity mocked by this fixture
     * 
     * @return array
     */
    public function toResponse(): array
    {
        return $this->attributes;
    }

    /**
     * Returns the database representation of the entity mocked by this fixture
     * 
     * @return array
     */
    public function toDatabase(): array
    {
        return $this->attributes;
    }
}
