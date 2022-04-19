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
            if ($cachedTimestamp) {
                $version = $assetTimestamp($url);
            }
            if (!isset($version)) {
                $version = $queryVersion;
            }
            $url .= '?v=' . $version;
        }

        echo "<link rel=\"stylesheet\" type=\"text/css\" href=\"$baseurl$url\"";
        if (isset($options['media'])) {
            echo " media=\"{$options['media']}\"";
        }
        echo ">\n";
    }
}

if (!empty($js)) {
    $jsBaseUrl = Configure::read('App.jsBaseUrl');
    foreach ($js as $path) {
        $url = $this->Html->assetUrl($path, ['pathPrefix' => $jsBaseUrl, 'ext' => '.js']);
        if (!empty($me)) {
            if ($cachedTimestamp) {
                $version = $assetTimestamp($url);
            }
            if (!isset($version)) {
                $version = $queryVersion;
            }
            $url .= '?v=' . $version;
        }
        echo "<script type=\"text/javascript\" src=\"$baseurl$url\"></script>\n";
    }
}

if ($cachedTimestamp && $cacheChanged) {
    Cache::write('asset_timestamp_cache', $timestamps, '_cake_core_');
}

if (!empty($meta)) {
    if (!is_array($meta) || !isset($meta[0])) {
        $meta = array($meta);
    }
    foreach ($meta as $item) {
        if (is_array($item)) {
            $type = $item[0];
            $url = empty($item[1]) ? null : $item[1];
            $options = empty($item[2]) ? array() : $item[2];
        } else {
            $type = $item;
            $url = null;
            $options = array();
        }
        echo $this->Html->meta($type, $url, $options);
    }
}
