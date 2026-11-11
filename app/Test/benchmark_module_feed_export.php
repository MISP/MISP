<?php
/** Assemble streamed Python-generated chunks through the actual disk-backed writer. */
require_once __DIR__ . '/../Lib/Tools/ModuleFeedExportTool.php';
set_time_limit(0); // Same as EventShell::exportModuleFeed; no aggregate HTTP deadline.
$parts = $argv[1] ?? '';
$count = (int)($argv[2] ?? 5000);
$root = $argv[3] ?? sys_get_temp_dir() . '/feed-benchmark-' . bin2hex(random_bytes(8));
if (!is_file($parts) || $count < 1) { throw new InvalidArgumentException('Usage: php benchmark_module_feed_export.php parts.jsonl count [output_directory]'); }
$tool = new ModuleFeedExportTool($root);
$tool->create(1, ['id' => 7], 'misp_feed', range(1, $count));
$input = fopen($parts, 'rb');
$start = microtime(true);
$tool->generate(1, function ($id) use ($input) {
    $line = fgets($input);
    if ($line === false) { throw new RuntimeException('Missing event response.'); }
    usleep(2000); // Small per-request latency; aggregate deliberately exceeds a web deadline.
    return json_decode($line, true, 512, JSON_THROW_ON_ERROR);
}, function ($done, $total, $message) {
    if ($done % 1000 === 0) { fwrite(STDERR, json_encode(['assembled' => $done, 'message' => $message]) . "\n"); }
});
fclose($input);
$status = $tool->status(1, ['id' => 7]);
$path = $tool->artifact(1, ['id' => 7]);
$zip = new ZipArchive(); $zip->open($path);
$manifest = json_decode($zip->getFromName('manifest.json'), true, 512, JSON_THROW_ON_ERROR);
if (count($manifest) !== $count || $zip->numFiles !== $count + 2) { throw new RuntimeException('Incomplete feed archive.'); }
$zip->close();
echo json_encode(['events' => $status['events'], 'archive_bytes' => $status['bytes'], 'sha256' => $status['sha256'],
    'seconds' => round(microtime(true) - $start, 2), 'php_peak_bytes' => memory_get_peak_usage(true), 'artifact' => $path]) . "\n";
