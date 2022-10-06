<?php
$cachedTimestamp = Configure::read('Asset.timestamp') === 'cached';
if ($cachedTimestamp) {
    $timestamps = Cache::read('asset_timestamp_cache', '_cake_core_');
    $cacheChanged = false;
}

$assetTimestamp = function ($url) use (&$timestamps, &$cacheChanged) {
    if (isset($timestamps[$url])) {
        return $timestamps[$url];
    } else {
        $file = WWW_ROOT . $url;
        if (file_exists($file)) {
            if ($version = filemtime($file)) {
                $timestamps[$url] = $version;
                $cacheChanged = true;
                return $version;
            }
        }
    }
    return null;
};

$preload = [];

if (!empty($css)) {
    $cssBaseUrl = Configure::read('App.cssBaseUrl');
    foreach ($css as $item) {
        if (is_array($item)) {
            $path = $item[0];
            $options = empty($item[1]) ? [] : $item[1];
        } else {
            $path = $item;
            $options = [];
        }

        $url = $this->Html->assetUrl($path, ['pathPrefix' => $cssBaseUrl, 'ext' => '.css']);
        if (!empty($me)) {
            $version = $cachedTimestamp ? $assetTimestamp($url) : null;
            if (!$version) {
                $version = $queryVersion;
            }
            $url .= '?v=' . $version;
        }

        echo "<link rel=\"stylesheet\" href=\"$baseurl$url\"";
        if (isset($options['media'])) {
            echo " media=\"{$options['media']}\"";
        }
        echo ">\n";

        if (!empty($options['preload'])) {
            $preload[$url] = 'style';
        }
    }
}

if (!empty($js)) {
    $jsBaseUrl = Configure::read('App.jsBaseUrl');
    foreach ($js as $item) {
        if (is_array($item)) {
            $path = $item[0];
            $options = empty($item[1]) ? [] : $item[1];
        } else {
            $path = $item;
            $options = [];
        }

        $url = $this->Html->assetUrl($path, ['pathPrefix' => $jsBaseUrl, 'ext' => '.js']);
        if (!empty($me)) {
            $version = $cachedTimestamp ? $assetTimestamp($url) : null;
            if (!$version) {
                $version = $queryVersion;
            }
            $url .= '?v=' . $version;
        }
        echo "<script src=\"$baseurl$url\"></script>\n";

        if (!empty($options['preload'])) {
            $preload[$url] = 'script';
        }
    }
}

if ($cachedTimestamp && $cacheChanged) {
    Cache::write('asset_timestamp_cache', $timestamps, '_cake_core_');
}

if (!empty($preload)) {
    $link = [];
    foreach ($preload as $url => $type) {
        $link[] = "<$url>;rel=preload;as=$type";
    }
    $this->response->header('Link', implode(',', $link));
}
