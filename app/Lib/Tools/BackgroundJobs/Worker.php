<?php

declare(strict_types=1);

class Worker implements JsonSerializable
{
    /** @var integer|null */
    private $pid;

    /** @var string */
    private $queue;

    /**
     * OS user
     *
     * @var string|null
     */
    private $user;

    /**
     * creation time (UNIX timestamp)
     *
     * @var integer
     */
    private $createdAt;

    /**
     * last update time (UNIX timestamp)
     *
     * @var integer|null
     */
    private $updatedAt;

    /**
     * status id
     *
     * @var integer
     */
    private $status;

    const
        STATUS_RUNNING = 1,
        STATUS_FAILED = 2,
        STATUS_UNKNOWN = 3;

    public function __construct(array $properties)
    {
        $this->pid = $properties['pid'];
        $this->queue = $properties['queue'];
        $this->user = $properties['user'];
        $this->createdAt = $properties['createdAt'] ?? time();
        $this->updatedAt = $properties['updatedAt'] ?? null;
        $this->status = $properties['status'] ?? self::STATUS_UNKNOWN;
    }

    public function jsonSerialize(): array
    {
        return [
            'pid' => $this->pid,
            'queue' => $this->queue,
            'user' => $this->user,
            'createdAt' => $this->createdAt,
            'updatedAt' => $this->updatedAt,
            'status' => $this->status,
        ];
    }

    public function pid(): ?int
    {
        return $this->pid;
    }

    public function queue(): string
    {
        return $this->queue;
    }

    public function user(): ?string
    {
        return $this->user;
    }

    public function createdAt(): int
    {
        return $this->createdAt;
    }

    public function updatedAt(): ?int
    {
        return $this->updatedAt;
    }

    public function status(): int
    {
        return $this->status;
    }

    public function setStatus(int $status)
    {
        $this->status = $status;
    }

    public function setUpdatedAt(int $updatedAt)
    {
        $this->updatedAt = $updatedAt;
    }
}
