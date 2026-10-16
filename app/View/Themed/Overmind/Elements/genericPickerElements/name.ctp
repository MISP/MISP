<?php
if (is_array($name)) {
    if (isset($name['label'])) {
        echo $this->TagChip->chip([
            'name' => $name['name'],
            'colour' => $name['label']['background'] ?? null,
        ], ['searchUrl' => '']);
    } else {
        echo h($name);
    }
} else {
    echo h($name);
}
