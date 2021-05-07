<?php

declare(strict_types=1);

namespace Helper\Fixture;

interface FixtureInterface
{
    /**
     * @param array<mixed> $attributes
     * 
     * @return self
     */
    public static function fake(array $attributes = []): self;

    /**
     * @param array<mixed> $attributes
     * 
     * @return void
     */
    public function set(array $attributes): void;

    /**
     * @return array<mixed>
     */
    public function toRequest(): array;

    /**
     * @return array<mixed>
     */
    public function toResponse(): array;

    /**
     * @return array<mixed>
     */
    public function toDatabase(): array;
}
