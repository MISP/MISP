<?php
    $data = $this->Hash->extract($row, $field['data_path']);
    $lines = '';
    $status_colours = [
        0 => 'secondary',
        1 => 'success',
        2 => 'warning',
        3 => 'danger'
    ];
    foreach ($data as $healthElement) {
        $name = h($healthElement['name']);
        if (!empty($healthElement['url'])) {
            $name = sprintf(
                '<a href="%s/%s">%s</a>',
                $baseurl,
                $healthElement['url'],
                $name
            );
        }
        $lines .= sprintf(
            '<p><span class="text-%s"><i class="fas fa-circle" ></i></span> %s: %s</p>',
            $status_colours[$healthElement['health']],
            $name,
            h($healthElement['message'])
        );
    }
    echo $lines;
?>
