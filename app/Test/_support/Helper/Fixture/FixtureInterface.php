<?php

namespace Helper\Fixture;

interface FixtureInterface
{
    public static function fake(array $attributes = []): self;

    public function set(array $attributes);

    public function toRequest(): array;

    public function toResponse(): array;

    public function toDatabase(): array;
}
