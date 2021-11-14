<?php
class ProcessException extends Exception
{
    private $stderr;

    private $stdout;

    /**
     * @param string $command
     * @param int $returnCode
     * @param string $stderr
     * @param string $stdout
     */
    public function __construct($command, $returnCode, $stderr, $stdout)
    {
        $message = "Command '$command' return error code $returnCode. STDERR: '$stderr', STDOUT: '$stdout'";
        $this->stderr = $stderr;
        $this->stdout = $stdout;
        parent::__construct($message, $returnCode);
    }

    public function stderr()
    {
        return $this->stderr;
    }

    public function stdout()
    {
        return $this->stdout;
    }
}

class ProcessTool
{
    /**
     * @param string|array $command
     * @param string|null $cwd
     * @return string Stdout
     * @throws ProcessException
     */
    public static function execute($command, $cwd = null)
    {
        $descriptorSpec = [
            1 => ["pipe", "w"], // stdout
            2 => ["pipe", "w"], // stderr
        ];

        if (is_array($command)) {
            $command = implode(' ', $command);
        }
        $process = proc_open($command, $descriptorSpec, $pipes, $cwd);
        if (!$process) {
            throw new Exception("Command '$command' could be started.");
        }

        $stdout = stream_get_contents($pipes[1]);
        if ($stdout === false) {
            throw new Exception("Could not get STDOUT of command.");
        }
        fclose($pipes[1]);

        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $returnCode = proc_close($process);
        if ($returnCode !== 0) {
            throw new ProcessException($command, $returnCode, $stderr, $stdout);
        }

        return $stdout;
    }
}
