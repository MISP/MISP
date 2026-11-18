<?php
/** Disk-backed feed assembly; only a single event response is in memory at once. */
class ModuleFeedExportTool
{
    const TTL = 86400;
    private $root;

    public function __construct($root = null)
    {
        $this->root = $root ?: TMP . 'module_feed_exports';
        if (!is_dir($this->root) && !mkdir($this->root, 0700, true)) {
            throw new RuntimeException('Could not create feed export storage.');
        }
    }

    private function directory($id)
    {
        if (!preg_match('/^[1-9][0-9]*$/D', (string)$id)) {
            throw new InvalidArgumentException('Invalid export job.');
        }
        return $this->root . DIRECTORY_SEPARATOR . $id;
    }

    private function save($dir, array $meta)
    {
        $meta['updated'] = time();
        $data = json_encode($meta, JSON_THROW_ON_ERROR);
        if (file_put_contents($dir . '/status.tmp', $data, LOCK_EX) !== strlen($data) ||
            !rename($dir . '/status.tmp', $dir . '/status.json')) {
            throw new RuntimeException('Could not save export progress.');
        }
    }

    public function create($id, array $user, $module, array $selection)
    {
        $this->purgeExpired();
        $dir = $this->directory($id);
        if (!mkdir($dir, 0700)) {
            throw new RuntimeException('Could not create export job storage.');
        }
        $request = ['selection' => $selection, 'module' => $module, 'owner' => $user['id']];
        $json = json_encode($request, JSON_THROW_ON_ERROR);
        if (file_put_contents($dir . '/request.json', $json, LOCK_EX) !== strlen($json)) {
            throw new RuntimeException('Could not save export selection.');
        }
        $this->save($dir, ['id' => (int)$id, 'owner' => $user['id'], 'module' => $module,
            'status' => 'queued', 'done' => 0, 'total' => count($selection), 'events' => 0,
            'expires' => time() + self::TTL]);
    }

    public function request($id)
    {
        return json_decode(file_get_contents($this->directory($id) . '/request.json'), true, 512, JSON_THROW_ON_ERROR);
    }

    public function status($id, array $user)
    {
        $dir = $this->directory($id);
        if (!is_file($dir . '/status.json')) {
            throw new RuntimeException('Export job not found or expired.');
        }
        $meta = json_decode(file_get_contents($dir . '/status.json'), true, 512, JSON_THROW_ON_ERROR);
        if ((string)$meta['owner'] !== (string)$user['id']) {
            throw new RuntimeException('Export job not found or expired.');
        }
        if ($meta['expires'] < time()) {
            if ($this->fail($id, 'Export job expired.', 'expired')) {
                $meta['status'] = 'expired';
            }
        }
        unset($meta['owner']);
        return $meta;
    }

    public function artifact($id, array $user)
    {
        $status = $this->status($id, $user);
        $path = $this->directory($id) . '/feed.zip';
        if ($status['status'] !== 'ready' || !is_file($path)) {
            throw new RuntimeException('Export is not ready or has expired.');
        }
        return $path;
    }

    private function clean($dir)
    {
        foreach (glob($dir . '/work/*') ?: [] as $path) {
            unlink($path);
        }
        if (is_dir($dir . '/work')) { rmdir($dir . '/work'); }
        foreach (['part.zip', 'feed.partial.zip', 'request.json'] as $name) {
            if (is_file($dir . '/' . $name)) { unlink($dir . '/' . $name); }
        }
    }

    public function fail($id, $message, $state = 'failed')
    {
        $dir = $this->directory($id);
        $lock = fopen($dir . '/run.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            if ($lock) { fclose($lock); }
            return false;
        }
        try { $this->markFailed($id, $message, $state); }
        finally { flock($lock, LOCK_UN); fclose($lock); }
        return true;
    }

    private function markFailed($id, $message, $state = 'failed')
    {
        $dir = $this->directory($id);
        $this->clean($dir);
        if (is_file($dir . '/feed.zip')) { unlink($dir . '/feed.zip'); }
        $meta = json_decode(file_get_contents($dir . '/status.json'), true, 512, JSON_THROW_ON_ERROR);
        $meta['status'] = $state;
        $meta['message'] = $message;
        $meta['expires'] = time() + self::TTL;
        $this->save($dir, $meta);
    }

    public function purgeExpired()
    {
        foreach (glob($this->root . '/*', GLOB_ONLYDIR) ?: [] as $dir) {
            if (!is_file($dir . '/status.json')) { continue; }
            $meta = json_decode(file_get_contents($dir . '/status.json'), true);
            if (!$meta || ($meta['expires'] ?? PHP_INT_MAX) >= time()) { continue; }
            $lock = fopen($dir . '/run.lock', 'c');
            if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) { if ($lock) { fclose($lock); } continue; }
            $this->clean($dir);
            foreach (glob($dir . '/*') ?: [] as $path) { if (is_file($path)) { unlink($path); } }
            rmdir($dir);
            fclose($lock);
        }
    }

    private function write($stream, $text)
    {
        $length = strlen($text);
        for ($offset = 0; $offset < $length;) {
            $written = fwrite($stream, substr($text, $offset));
            if (!$written) { throw new RuntimeException('Could not write feed output (check disk space).'); }
            $offset += $written;
        }
    }

    private function enforceLimits(array $reply, $selected, $bytes)
    {
        $limits = $reply['feed_limits'] ?? null;
        if (!is_array($limits)) { throw new RuntimeException('Module does not support incremental feed exports.'); }
        foreach (['max_events', 'max_size_mb'] as $key) {
            if (!isset($limits[$key]) || !is_int($limits[$key]) || $limits[$key] < 0) {
                throw new RuntimeException('Invalid feed limits.');
            }
        }
        if (($limits['max_events'] && $selected > $limits['max_events']) ||
            ($limits['max_size_mb'] && $bytes > $limits['max_size_mb'] * 1024 * 1024)) {
            throw new RuntimeException('The selected feed exceeds its configured event or disk size budget.');
        }
    }

    public function generate($id, callable $produce, ?callable $progress = null)
    {
        $dir = $this->directory($id);
        $lock = fopen($dir . '/run.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            if ($lock) { fclose($lock); }
            return false; // Another worker owns this job; never remove its files.
        }
        $manifest = $hashes = null;
        $zip = null;
        try {
            $meta = json_decode(file_get_contents($dir . '/status.json'), true, 512, JSON_THROW_ON_ERROR);
            if ($meta['status'] === 'ready') { return true; }
            if (in_array($meta['status'], ['failed', 'expired'], true)) { return false; }
            $request = $this->request($id);
            if ($meta['status'] !== 'queued' || $meta['expires'] < time()) {
                throw new RuntimeException('Export job was interrupted or expired; submit a new selection.');
            }
            if (!class_exists('ZipArchive')) { throw new RuntimeException('PHP ZIP support is required.'); }
            mkdir($dir . '/work', 0700);
            $manifest = fopen($dir . '/work/manifest.json', 'wb');
            $hashes = fopen($dir . '/work/hashes.csv', 'wb');
            if (!$manifest || !$hashes) { throw new RuntimeException('Could not create feed indexes.'); }
            $this->write($manifest, '{');
            $zip = new ZipArchive();
            if ($zip->open($dir . '/feed.partial.zip', ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
                throw new RuntimeException('Could not create feed ZIP.');
            }
            $meta['status'] = 'running';
            $meta['expires'] = time() + self::TTL;
            $this->save($dir, $meta);
            $bytes = 2;
            foreach ($request['selection'] as $selected) {
                $reply = $produce($selected);
                if ($reply !== null) {
                    if (!is_array($reply) || isset($reply['error']) || !isset($reply['data']) || !is_string($reply['data'])) {
                        throw new RuntimeException('The feed module failed to serialize an event.');
                    }
                    $raw = base64_decode($reply['data'], true);
                    if ($raw === false || file_put_contents($dir . '/part.zip', $raw) !== strlen($raw)) {
                        throw new RuntimeException('Invalid event feed part.');
                    }
                    unset($raw);
                    $part = new ZipArchive();
                    $opened = false;
                    try {
                        $opened = $part->open($dir . '/part.zip') === true;
                        if (!$opened || $part->numFiles < 2 || $part->numFiles > 3) {
                            throw new RuntimeException('Invalid event feed part.');
                        }
                        $indexRaw = $part->getFromName('manifest.json', 1048577);
                        if ($indexRaw === false || strlen($indexRaw) > 1048576) { throw new RuntimeException('Invalid part manifest.'); }
                        $index = json_decode($indexRaw, true, 512, JSON_THROW_ON_ERROR);
                        if (!is_array($index) || count($index) > 1) { throw new RuntimeException('Expected a single-event feed part.'); }
                        if ($part->locateName('hashes.csv') === false || $part->numFiles !== count($index) + 2) {
                            throw new RuntimeException('Invalid part files.');
                        }
                        foreach ($index as $uuid => $entry) {
                            if (!preg_match('/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/D', $uuid)) {
                                throw new RuntimeException('Invalid event UUID in feed part.');
                            }
                            $name = $uuid . '.json';
                            $path = $dir . '/work/' . $name;
                            if (file_exists($path)) { throw new RuntimeException('Duplicate event UUID in feed selection.'); }
                            $source = $part->getStream($name);
                            $target = fopen($path, 'xb');
                            if (!$source || !$target) { throw new RuntimeException('Missing event file in feed part.'); }
                            try {
                                while (!feof($source)) {
                                    $buffer = fread($source, 65536);
                                    if ($buffer === false) { throw new RuntimeException('Could not read feed part.'); }
                                    $bytes += strlen($buffer);
                                    $this->enforceLimits($reply, count($request['selection']), $bytes);
                                    $this->write($target, $buffer);
                                }
                            } finally { fclose($source); fclose($target); }
                            if (!$zip->addFile($path, $name)) { throw new RuntimeException('Could not add event to ZIP.'); }
                            $item = ($meta['events'] ? ',' : '') . json_encode($uuid) . ':' . json_encode($entry, JSON_THROW_ON_ERROR);
                            $bytes += strlen($item);
                            $this->write($manifest, $item);
                            $meta['events']++;
                        }
                        $source = $part->getStream('hashes.csv');
                        if (!$source) { throw new RuntimeException('Missing part hash index.'); }
                        try {
                            while (($row = fgetcsv($source, 256, ',', '"', '')) !== false) {
                                if (count($row) !== 2 || !preg_match('/^[0-9a-f]{32}$/D', $row[0]) || !isset($index[$row[1]])) {
                                    throw new RuntimeException('Invalid part hash index.');
                                }
                                $text = $row[0] . ',' . $row[1] . "\n";
                                $bytes += strlen($text);
                                $this->enforceLimits($reply, count($request['selection']), $bytes);
                                $this->write($hashes, $text);
                            }
                        } finally { fclose($source); }
                        $this->enforceLimits($reply, count($request['selection']), $bytes);
                    } finally { if ($opened) { $part->close(); } unlink($dir . '/part.zip'); }
                }
                unset($reply);
                $meta['done']++;
                $meta['expires'] = time() + self::TTL;
                $this->save($dir, $meta);
                if ($progress) { $progress($meta['done'], $meta['total'], 'Generating feed.'); }
            }
            if (!$meta['events']) { throw new RuntimeException('No selected events passed access/publication/distribution filters.'); }
            $this->write($manifest, '}');
            fclose($manifest); $manifest = null;
            fclose($hashes); $hashes = null;
            if (!$zip->addFile($dir . '/work/manifest.json', 'manifest.json') ||
                !$zip->addFile($dir . '/work/hashes.csv', 'hashes.csv')) {
                throw new RuntimeException('Could not add feed indexes to ZIP.');
            }
            if ($progress) { $progress($meta['total'], $meta['total'], 'Finalising ZIP archive.'); }
            if (!$zip->close()) { throw new RuntimeException('Could not finish feed ZIP.'); }
            $zip = null;
            $meta['bytes'] = filesize($dir . '/feed.partial.zip');
            $meta['sha256'] = hash_file('sha256', $dir . '/feed.partial.zip');
            if ($meta['bytes'] === false || $meta['sha256'] === false) {
                throw new RuntimeException('Could not verify feed ZIP.');
            }
            if (!rename($dir . '/feed.partial.zip', $dir . '/feed.zip')) { throw new RuntimeException('Could not publish feed download.'); }
            $meta['status'] = 'ready';
            $meta['expires'] = time() + self::TTL;
            $this->save($dir, $meta);
            $this->clean($dir);
            return true;
        } catch (Throwable $e) {
            if ($zip) { try { $zip->close(); } catch (Throwable $ignored) {} }
            if (is_resource($manifest)) { fclose($manifest); }
            if (is_resource($hashes)) { fclose($hashes); }
            $this->markFailed($id, 'Feed generation failed. Check module access, filters, limits and disk space; no partial feed is available.');
            throw $e;
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
}
