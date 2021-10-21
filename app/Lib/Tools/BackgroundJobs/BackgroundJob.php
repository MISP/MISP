<?php

declare(strict_types=1);

App::uses('Model', 'Model');

class BackgroundJob implements JsonSerializable
{
    public const
        STATUS_WAITING = 1,
        STATUS_RUNNING = 2,
        STATUS_FAILED = 3,
        STATUS_COMPLETED = 4;

    /**
     * Job id
     *
     * @var string
     */
    private $id;

    /**
     * Command name
     *
     * @var string
     */
    private $command;

    /**
     * Command arguments
     *
     * @var array
     */
    private $args;

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

    /**
     * Job metadata
     *
     * @var array
     */
    private $metadata;

    /**
     * Process return code
     *
     * @var integer
     */
    private $returnCode;

    public function __construct(array $properties)
    {
        $this->id = $properties['id'];
        $this->command = $properties['command'];
        $this->args = $properties['args'] ?? [];
        $this->createdAt = $properties['createdAt'] ?? time();
        $this->updatedAt = $properties['updatedAt'] ?? null;
        $this->status = $properties['status'] ?? self::STATUS_WAITING;
        $this->metadata = $properties['metadata'] ?? [];
    }

    /**
     * Run the job command
     *
     * @return self
     */
    public function run(): self
    {
        $descriptorSpec = [
            1 => ["pipe", "w"], // stdout
            2 => ["pipe", "w"], // stderr
        ];

        $process = proc_open(
            [
                ROOT . DS . 'app' . DS . 'Console' . DS . 'cake',
                $this->command(),
                ...$this->args()
            ],
            $descriptorSpec,
            $pipes
        );

        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $this->returnCode = proc_close($process);

        if ($this->returnCode === 0) {
            $this->setStatus(BackgroundJob::STATUS_COMPLETED);

            CakeLog::info("[JOB ID: {$this->id()}] - completed.");
        } else {
            $this->setStatus(BackgroundJob::STATUS_FAILED);

            CakeLog::error("[JOB ID: {$this->id()}] - failed with error code {$this->returnCode}. STDERR: {$stderr}. STDOUT: {$stdout}.");
        }

        return $this;
    }

    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'command' => $this->command,
            'args' => $this->args,
            'createdAt' => $this->createdAt,
            'updatedAt' => $this->updatedAt,
            'status' => $this->status,
            'metadata' => $this->metadata,
        ];
    }

    public function id(): string
    {
        return $this->id;
    }

    public function command(): string
    {
        return $this->command;
    }

    public function args(): array
    {
        return $this->args;
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

    public function metadata(): array
    {
        return $this->metadata;
    }

    public function returnCode(): int
    {
        return $this->returnCode;
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
