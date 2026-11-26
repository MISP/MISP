<?php

class SystemClock implements \Psr\Clock\ClockInterface
{
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable();
    }
}
