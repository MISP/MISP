<?php
/*
 * The column browser's stylesheet and script as a JSON object
 * ({css: {path, url}, js: {path, url}}) for loadIndexFilterBrowser()
 * (mispOvermind.js), at the URLs the asset loader would give them.
 */
$cachedTimestamp = Configure::read('Asset.timestamp') === 'cached';
$asset = function ($ext) use ($cachedTimestamp, $queryVersion) {
    $url = $this->Html->assetUrl('index-filter-browser', [
        'pathPrefix' => Configure::read($ext === 'js' ? 'App.jsBaseUrl' : 'App.cssBaseUrl'),
        'ext' => '.' . $ext,
    ]);
    $version = $cachedTimestamp && file_exists(WWW_ROOT . $url) ? filemtime(WWW_ROOT . $url) : null;
    return ['path' => $url, 'url' => $url . '?v=' . ($version ?: $queryVersion)];
};
echo json_encode(['css' => $asset('css'), 'js' => $asset('js')], JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES);
