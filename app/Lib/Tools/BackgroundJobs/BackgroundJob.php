<?php

declare(strict_types=1);

class BackgroundJob implements JsonSerializable
{
    const
        STATUS_WAITING = 1,
        STATUS_RUNNING = 2,
        STATUS_FAILED = 3,
        STATUS_COMPLETED = 4;

    /** @var string */
    private $id;

    /** @var string */
    private $command;

    /** @var array */
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

    /**@var integer */
    private $status;

    /** @var integer */
    private $progress;

    /** @var string|null */
    private $output;

    /** @var string|null */
    private $error;

    /** @var array */
    private $metadata;

    /** @var integer */
    private $returnCode;

    public function __construct(array $properties)
    {
        $this->id = $properties['id'];
        $this->command = $properties['command'];
        $this->args = $properties['args'] ?? [];
        $this->createdAt = $properties['createdAt'] ?? time();
        $this->updatedAt = $properties['updatedAt'] ?? null;
        $this->status = $properties['status'] ?? self::STATUS_WAITING;
        $this->error = $properties['error'] ?? null;
        $this->progress = $properties['progress'] ?? 0;
        $this->metadata = $properties['metadata'] ?? [];
    }

    /**
     * Run the job command
     */
    public function run(): void
    {
        $descriptorSpec = [
            1 => ["pipe", "w"], // stdout
            2 => ["pipe", "w"], // stderr
        ];

        $process = proc_open(
            array_merge(
                [
                    ROOT . DS . 'app' . DS . 'Console' . DS . 'cake',
                    $this->command(),
                ],
                $this->args()
            ),
            $descriptorSpec,
            $pipes,
            null,
            ['BACKGROUND_JOB_ID' => $this->id]
        );

        $this->pool($process, $pipes);

        if ($this->returnCode === 0 && empty($stderr)) {
            $this->setStatus(BackgroundJob::STATUS_COMPLETED);
            $this->setProgress(100);
        } else {
            $this->setStatus(BackgroundJob::STATUS_FAILED);
        }
    }

    private function pool($process, array $pipes)
    {
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $this->output = '';
        $this->error = '';

        while (true) {
            $read = [$pipes[1], $pipes[2]];
            $write = null;
            $except = null;

            if (false === ($changedStreams = stream_select($read, $write, $except, 5))) {
                throw new RuntimeException("Could not select stream");
            } elseif ($changedStreams > 0) {
                $this->output .= stream_get_contents($pipes[1]);
                $this->error .= stream_get_contents($pipes[2]);
            }
            $status = proc_get_status($process);
            if (!$status['running']) {
                // Just in case read rest data from stream
                $this->output .= stream_get_contents($pipes[1]);
                $this->error .= stream_get_contents($pipes[2]);

                fclose($pipes[1]);
                fclose($pipes[2]);

                proc_close($process);
                $this->returnCode = $status['exitcode'];
                break;
            }
        }
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
            'output' => $this->output,
            'error' => $this->error,
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

    public function progress(): int
    {
        return $this->progress;
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

    public function output(): ?string
    {
        return $this->output;
    }

    public function error(): ?string
    {
        return $this->error;
    }

    public function metadata(): array
    {
        return $this->metadata;
    }

    public function returnCode(): int
    {
        return $this->returnCode;
    }

    public function setStatus(int $status)
    {
        $this->status = $status;
    }

    public function setOutput(?string $output)
    {
        $this->output = $output;
    }

    public function setError(?string $error)
    {
        $this->error = $error;
    }

    public function setProgress(int $progress)
    {
        $this->progress = $progress;
    }

    public function setUpdatedAt(int $updatedAt)
    {
        $this->updatedAt = $updatedAt;
    }
}
