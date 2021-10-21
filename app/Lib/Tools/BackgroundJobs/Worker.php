<?php

declare(strict_types=1);

App::uses('Model', 'Model');

class Worker implements JsonSerializable
{
    /**
     * Worker pid
     *
     * @var integer
     */
    private $pid;

    /**
     * Worker queue
     *
     * @var string
     */
    private $queue;

    /**
     * Creation time (UNIX timestamp)
     *
     * @var integer
     */
    private $createdAt;

    /**
     * Last update time (UNIX timestamp)
     *
     * @var integer|null
     */
    private $updatedAt;

    /**
     * Job status id
     *
     * @var integer
     */
    private $status;

    public const
        STATUS_RUNNING = 1,
        STATUS_FAILED = 2,
        STATUS_UNKNOWN = 3;

    public function __construct(array $properties)
    {
        $this->pid = $properties['pid'];
        $this->queue = $properties['queue'];
        $this->createdAt = $properties['createdAt'] ?? time();
        $this->updatedAt = $properties['updatedAt'] ?? null;
        $this->status = $properties['status'] ?? self::STATUS_RUNNING;
    }

    public function jsonSerialize(): array
    {
        return [
            'pid' => $this->pid,
            'queue' => $this->queue,
            'createdAt' => $this->createdAt,
            'updatedAt' => $this->updatedAt,
            'status' => $this->status,
        ];
    }

    public function pid(): int
    {
        return $this->pid;
    }

    public function queue(): string
    {
        return $this->queue;
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

    public function setStatus(int $status): void
    {
        $this->status = $status;
    }

    public function setUpdatedAt(int $updatedAt): void
    {
        $this->updatedAt = $updatedAt;
    }
}
