<?php
$index = 0;

foreach ($allAccessibleApis as $category => $content) {

    ob_start();

    foreach ($content as $action => $url) {
        echo $this->element('genericElementsBS5/Cards/card_query', [
            'title' => $action,
            'url' => $url[0],
            'method' => $url[1],
        ]);
    }

    $contentHtml = ob_get_clean();

    echo $this->element('genericElementsBS5/Cards/card_category', [
        'title' => ucfirst($category),
        'content' => $contentHtml,
        'collapsed' => $index !== 0
    ]);

    $index++;
}
?>