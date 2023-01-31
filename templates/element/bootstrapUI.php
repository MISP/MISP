<?php
if (!empty($element)) {
    echo $this->Bootstrap->{$element}([
        'text' => $text,
        'variant' => $variant,
    ]);
}