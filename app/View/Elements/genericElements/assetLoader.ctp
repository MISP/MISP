<?php
    if (!empty($css)) {
        if (!is_array($css) || !isset($css[0])) {
            $css = array($css);
        }
        foreach ($css as $item) {
            if (is_array($item)) {
                $path = $item[0];
                $options = empty($item[1]) ? array() : $item[1];
            } else {
                $path = $item;
                $options = array();
            }
            if (!empty($me)) {
                $path .= '.css?' . $queryVersion;
            }
            echo $this->Html->css($path, $options);
        }
    }

    if (!empty($js)) {
        if (!is_array($js) || !isset($js[0])) {
            $js = array($js);
        }
        foreach ($js as $item) {
            if (is_array($item)) {
                $path = $item[0];
                $options = empty($item[1]) ? array() : $item[1];
            } else {
                $path = $item;
                $options = array();
            }
            if (!empty($me)) {
                $path .= '.js?' . $queryVersion;
            }
            echo $this->Html->script($path, $options);
        }
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

?>
