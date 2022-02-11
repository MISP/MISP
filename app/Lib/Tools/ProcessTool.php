<?php
class ProcessException extends Exception
{
    /** @var string */
    private $stderr;

    /** @var string */
    private $stdout;

    /**
     * @param string|array $command
     * @param int $returnCode
     * @param string $stderr
     * @param string $stdout
     */
    public function __construct($command, $returnCode, $stderr, $stdout)
    {
        $commandForException = is_array($command) ? implode(' ', $command) : $command;
        $message = "Command '$commandForException' return error code $returnCode.\nSTDERR: '$stderr'\nSTDOUT: '$stdout'";
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
    const LOG_FILE = APP . 'tmp/logs/exec-errors.log';

    /**
     * @param array $command If command is array, it is not necessary to escape arguments
     * @param string|null $cwd
     * @param bool $stderrToFile IF true, log stderrr output to LOG_FILE
     * @return string Stdout
     * @throws ProcessException
     * @throws Exception
     */
    public static function execute(array $command, $cwd = null, $stderrToFile = false)
    {
        $descriptorSpec = [
            1 => ["pipe", "w"], // stdout
            2 => ["pipe", "w"], // stderr
        ];

        if ($stderrToFile) {
            self::logMessage('Running command ' . implode(' ', $command));
            $descriptorSpec[2] = ["file", self::LOG_FILE, 'a'];
        }

        // PHP older than 7.4 do not support proc_open with array, so we need to convert values to string manually
        if (PHP_VERSION_ID < 70400) {
            $command = array_map('escapeshellarg', $command);
            $command = implode(' ', $command);
        }
        $process = proc_open($command, $descriptorSpec, $pipes, $cwd);
        if (!$process) {
            $commandForException = self::commandFormat($command);
            throw new Exception("Command '$commandForException' could be started.");
        }

        $stdout = stream_get_contents($pipes[1]);
        if ($stdout === false) {
            $commandForException = self::commandFormat($command);
            throw new Exception("Could not get STDOUT of command '$commandForException'.");
        }

        if ($stderrToFile) {
            $stderr = null;
        } else {
            $stderr = stream_get_contents($pipes[2]);
        }

        $returnCode = proc_close($process);

        if ($stderrToFile) {
            self::logMessage("Process finished with return code $returnCode");
        }

        if ($returnCode !== 0) {
            throw new ProcessException($command, $returnCode, $stderr, $stdout);
        }

        return $stdout;
    }

    /**
     * Get current process user name
     * @return string
     * @throws ProcessException
     */
    public static function whoami()
    {
        if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
            return posix_getpwuid(posix_geteuid())['name'];
        } else {
            return rtrim(self::execute(['whoami']));
        }
    }

    /**
     * @return string
     */
    public static function pythonBin()
    {
        return Configure::read('MISP.python_bin') ?: 'python3';
    }

    private static function logMessage($message)
    {
        $logMessage = '[' . date("Y-m-d H:i:s") . ' ' . getmypid() . "] $message\n";
        file_put_contents(self::LOG_FILE, $logMessage, FILE_APPEND | LOCK_EX);
    }

    /**
     * @param array|string $command
     * @return string
     */
    private static function commandFormat($command)
    {
        return  is_array($command) ? implode(' ', $command) : $command;
    }
}
