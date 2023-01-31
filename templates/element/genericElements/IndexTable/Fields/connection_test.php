<?php
    $data = $this->Hash->extract($row, $field['data_path'])[0];
    echo sprintf(
        '<div id="connection_test_%s"><span role="button" tabindex="0" aria-label="%s" title="%s" class="btn btn-primary btn-sm" onClick="%s">%s</span></div>',
        h($data),
        __('Test the connection to the remote instance'),
        __('Test the connection to the remote instance'),
        sprintf(
            "testConnection('%s');",
            h($data)
        ),
        __('Run')
    );
?>
