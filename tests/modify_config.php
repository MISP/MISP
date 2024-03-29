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
try {
    $newConfig = json_decode($argv[2], true, JSON_THROW_ON_ERROR);
} catch (Exception $e) {
    fail(2, "Could not decode new config, it is not JSON: " . $e->getMessage());
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

// Returns config file before modification
echo json_encode($config, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
