<?php
/** Disk-based gathering archive ingestion; JSON responses contain job metadata only. */
class GatheringFeedTool
{
    const MAX_BYTES = 10737418240;
    const MAX_EVENT_BYTES = 268435456;

    private static function limit($name, $default)
    {
        $value = Configure::read('Plugin.Gathering_' . $name);
        return filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) ?: $default;
    }

    public static function settings($settings)
    {
        if (is_string($settings)) {
            $settings = json_decode($settings, true);
        }
        $options = $settings['gathering'] ?? null;
        if (!is_array($options) || !isset($options['module']) ||
            !is_string($options['module']) || !preg_match('/\A[a-z][a-z0-9_]*\z/D', $options['module'])) {
            throw new InvalidArgumentException('Select a gathering module.');
        }
        $parameters = $options['parameters'] ?? [];
        if (is_string($parameters)) {
            if ($parameters === '') {
                $parameters = '{}';
            }
            $decoded = json_decode($parameters);
            if (!is_object($decoded) || json_last_error() !== JSON_ERROR_NONE) {
                throw new InvalidArgumentException('Gathering parameters must be a JSON object.');
            }
            $parameters = json_decode($parameters, true);
        }
        if (!is_array($parameters) || ($parameters && array_keys($parameters) === range(0, count($parameters) - 1))) {
            throw new InvalidArgumentException('Gathering parameters must be a JSON object.');
        }
        return ['module' => $options['module'], 'parameters' => $parameters];
    }

    public static function job($value, $identifier = null)
    {
        if (!is_array($value) || ($value['gathering_version'] ?? null) !== 2 ||
            ($value['source_format'] ?? null) !== 'misp' || !is_string($value['job_id'] ?? null) ||
            !preg_match('/\A[0-9a-f]{64}\z/D', $value['job_id']) ||
            ($identifier !== null && $value['job_id'] !== $identifier) ||
            !in_array($value['status'] ?? null, ['queued', 'running', 'ready', 'failed'], true)) {
            throw new UnexpectedValueException('Invalid gathering job response.');
        }
        if ($value['status'] === 'ready' &&
            (!is_int($value['archive_size'] ?? null) || $value['archive_size'] < 1 || $value['archive_size'] > self::limit('max_archive_bytes', self::MAX_BYTES) ||
            !is_string($value['sha256'] ?? null) || !preg_match('/\A[0-9a-f]{64}\z/D', $value['sha256']))) {
            throw new UnexpectedValueException('Invalid gathering archive metadata or size budget exceeded.');
        }
        return $value;
    }

    /** Flat, ordinary MISP feed files only. Never use ZipArchive::extractTo(). */
    public static function extractArchive($archivePath, $directory)
    {
        if (!class_exists('ZipArchive')) {
            throw new RuntimeException('The PHP zip extension is required for gathering feeds.');
        }
        $zip = new ZipArchive();
        if ($zip->open($archivePath, ZipArchive::RDONLY) !== true) {
            throw new UnexpectedValueException('Invalid gathering ZIP archive.');
        }
        $total = 0;
        $maxBytes = self::limit('max_expanded_bytes', self::MAX_BYTES);
        $maxFileBytes = self::limit('max_event_bytes', self::MAX_EVENT_BYTES);
        try {
            if (!mkdir($directory, 0700)) {
                throw new RuntimeException('Could not create the gathering feed directory.');
            }
            for ($index = 0; $index < $zip->numFiles; ++$index) {
                $stat = $zip->statIndex($index);
                $name = $stat['name'];
                $event = preg_match('/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json\z/D', $name);
                if (!$event && $name !== 'manifest.json' && $name !== 'hashes.csv') {
                    throw new UnexpectedValueException('Unsupported file or path in gathering ZIP.');
                }
                $zip->getExternalAttributesIndex($index, $system, $attributes);
                $kind = ($attributes >> 16) & 0170000;
                if (($kind !== 0 && $kind !== 0100000) || !empty($stat['encryption_method']) ||
                    $stat['size'] > $maxFileBytes || $total + $stat['size'] > $maxBytes) {
                    throw new UnexpectedValueException('Gathering ZIP entry type or size is unsupported.');
                }
                $input = $zip->getStream($name);
                $output = @fopen($directory . DIRECTORY_SEPARATOR . $name, 'xb');
                if ($input === false || $output === false) {
                    if (is_resource($input)) { fclose($input); }
                    if (is_resource($output)) { fclose($output); }
                    throw new UnexpectedValueException('Duplicate or unreadable gathering ZIP entry.');
                }
                $size = 0;
                $crc = hash_init('crc32b');
                try {
                    while (!feof($input)) {
                        $chunk = fread($input, 65536);
                        if ($chunk === false) { throw new RuntimeException('Could not read gathering ZIP entry.'); }
                        $size += strlen($chunk);
                        if ($size > $stat['size'] || $total + $size > $maxBytes) {
                            throw new UnexpectedValueException('Gathering ZIP expanded beyond its declared size.');
                        }
                        hash_update($crc, $chunk);
                        $offset = 0;
                        while ($offset < strlen($chunk)) {
                            $written = fwrite($output, substr($chunk, $offset));
                            if (!$written) { throw new RuntimeException('Could not write gathering feed file.'); }
                            $offset += $written;
                        }
                    }
                } finally {
                    fclose($input);
                    fclose($output);
                }
                if ($size !== $stat['size'] || hash_final($crc) !== sprintf('%08x', $stat['crc'] & 0xffffffff)) {
                    throw new UnexpectedValueException('Gathering ZIP entry is truncated or corrupt.');
                }
                $total += $size;
            }
            if (!is_file($directory . DIRECTORY_SEPARATOR . 'manifest.json')) {
                throw new UnexpectedValueException('Gathering ZIP has no manifest.json.');
            }
        } finally {
            $zip->close();
        }
    }

    /** Small status polls are separate from generation and streamed ZIP download. */
    public static function prepare($module, array $options, array $user, $root, $timeout = 86400, ?callable $wait = null)
    {
        GatheringFeedWorkspace::reap($root);
        $workspace = new GatheringFeedWorkspace($root, $module);
        try {
            $job = self::job($module->queryGathering($options['module'], $options['parameters'], $user));
            $workspace->jobId = $job['job_id'];
            $deadline = microtime(true) + $timeout;
            while (in_array($job['status'], ['queued', 'running'], true)) {
                if (microtime(true) >= $deadline) { throw new RuntimeException('Gathering generation timed out.'); }
                $wait ? $wait() : usleep(1000000);
                $job = self::job($module->gatheringJobStatus($workspace->jobId), $workspace->jobId);
            }
            if ($job['status'] !== 'ready') { throw new RuntimeException('Gathering generation failed; see module service logs.'); }
            $archive = $workspace->directory . DIRECTORY_SEPARATOR . 'feed.zip';
            $module->downloadGatheringArchive($workspace->jobId, $archive, $job['archive_size']);
            if (filesize($archive) !== $job['archive_size'] || !hash_equals($job['sha256'], hash_file('sha256', $archive))) {
                throw new UnexpectedValueException('Gathering archive size or SHA256 mismatch.');
            }
            self::extractArchive($archive, $workspace->feedDirectory);
            unlink($archive);
            return $workspace;
        } catch (Throwable $e) {
            $workspace->close();
            throw $e;
        }
    }
}

/** Owns temporary files only; it never inserts, updates or deletes a Feed row. */
class GatheringFeedWorkspace
{
    public $directory;
    public $feedDirectory;
    public $jobId;
    private $module;
    private $closed = false;
    private $lock;

    public function __construct($root, $module)
    {
        $this->directory = $root . DIRECTORY_SEPARATOR . 'gathering-' . bin2hex(random_bytes(16));
        if (!is_dir($root) || !mkdir($this->directory, 0700)) {
            throw new RuntimeException('Could not create gathering workspace.');
        }
        $this->feedDirectory = $this->directory . DIRECTORY_SEPARATOR . 'feed';
        $this->module = $module;
        $this->lock = fopen($this->directory . DIRECTORY_SEPARATOR . '.lock', 'xb');
        if (!$this->lock || !flock($this->lock, LOCK_EX)) {
            if (is_resource($this->lock)) { fclose($this->lock); }
            self::removeDirectory($this->directory);
            throw new RuntimeException('Could not lock gathering workspace.');
        }
    }

    public function close()
    {
        if ($this->closed) { return; }
        $this->closed = true;
        try {
            self::removeDirectory($this->directory);
        } finally {
            if (is_resource($this->lock)) { fclose($this->lock); }
            if ($this->jobId) {
                try { $this->module->releaseGatheringJob($this->jobId); }
                catch (Throwable $e) { error_log('Could not release gathering artifact; module retention cleanup will remove it.'); }
            }
        }
    }

    /** Recover disk space after a killed worker; live workspaces hold a file lock. */
    public static function reap($root, $maxAge = 172800)
    {
        foreach (new FilesystemIterator($root) as $entry) {
            if (!$entry->isDir() || $entry->isLink() || !preg_match('/\Agathering-[0-9a-f]{32}\z/D', $entry->getFilename()) ||
                $entry->getMTime() > time() - $maxAge) { continue; }
            $lock = @fopen($entry->getPathname() . DIRECTORY_SEPARATOR . '.lock', 'r+');
            if ($lock && flock($lock, LOCK_EX | LOCK_NB)) { self::removeDirectory($entry->getPathname()); }
            if (is_resource($lock)) { fclose($lock); }
        }
    }

    public static function removeDirectory($directory)
    {
        if (!is_dir($directory)) { return; }
        foreach (new FilesystemIterator($directory) as $entry) {
            if ($entry->isDir() && !$entry->isLink()) { self::removeDirectory($entry->getPathname()); }
            else { unlink($entry->getPathname()); }
        }
        rmdir($directory);
    }

    public function __destruct() { $this->close(); }
}
