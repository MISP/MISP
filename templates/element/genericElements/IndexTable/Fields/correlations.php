<?php
    $correlations = $this->Hash->extract($row, $field['data_path']);
    $scope_to_url = array(
        'event' => $baseurl . '/events/view'
    );
    $correlations_html = array();
    foreach ($correlations as $id => $name) {
        $correlations_html[] = sprintf(
            '<a href="%s%s" title="%s">%s</a>',
            $baseurl,
            sprintf(
                '%s/%s',
                $scope_to_url[empty($scope) ? 'event' : $scope],
                h($id)
            ),
            h($name),
            h($id)
        );
    }
    echo implode(' ', $correlations_html);
?>
