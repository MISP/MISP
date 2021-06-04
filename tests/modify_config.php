<?php
function fail($code, $message) {
    fwrite(STDERR, "$message\n");
    exit($code);
}

if (!isset($argv[2])) {
    fail(1, "Required arguments not provided.");
}
if (!in_array($argv[1], ['modify', 'replace'], true)) {
    fail(1, "Invalid argument '{$argv[1]}', it must be 'modify' or 'replace'.");
}
$newConfig = json_decode($argv[2], true);
if ($newConfig === null) {
    fail(2, "Could not decode new config, it is not JSON: " . json_last_error_msg());
}
if (!is_array($newConfig)) {
    fail(2, "Provided new config is not array, `" . gettype($newConfig) . "` given.");
}
$configFile = realpath(__DIR__ . '/../app/Config/config.php');
if ($configFile === false) {
    fail(3, "File $configFile not found.");
}
if (!is_readable($configFile)) {
    fail(3, "File $configFile is not readable.");
}
if (!is_writable($configFile)) {
    $owner = posix_getpwuid(fileowner($configFile))["name"] . ':' . posix_getgrgid(filegroup($configFile))["name"];
    $perms = substr(sprintf('%o', fileperms($configFile)), -4);
    fail(3, "File $configFile is not writeable (owner $owner, permissions $perms).");
}
if (function_exists('opcache_invalidate')) {
    opcache_invalidate($configFile, true);
}
require_once $configFile;
if (!isset($config)) {
    fail(3, "Original config variable not found.");
}
if ($argv[1] === 'modify') {
    $merged = array_replace_recursive($config, $newConfig);
} else {
    $merged = $newConfig;
}
file_put_contents($configFile, "<?php\n\$config = " . var_export($merged, true) . ';', LOCK_EX);

if (function_exists('opcache_invalidate')) {
    opcache_invalidate($configFile, true);
}
// Returns config file before modification
echo json_encode($config);
