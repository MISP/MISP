<?php
echo sprintf(
    '<span class="authkey">%s</span>%s<span class="authkey">%s</span>',
    h($data['authkey_start']),
    str_repeat('&bull;', 32),
    h($data['authkey_end'])
);
