<?php
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

$element = Hash::extract($row, $field['data_path']);

if (empty($element)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex flex-column gap-1">
    <div class="d-flex align-items-baseline gap-2 mb-0">
        <?php if($element['element_type'] === "Event") {
            if (!empty($element['Event'])) {
                printf(
                    '<a class="text-decoration-none d-inline-flex align-items-baseline gap-1" href="%s">'
                        . '<span class="badge bg-event">#%s</span>'
                        . '<span class="text-body">%s</span>'
                    . '</a>',
                    h($baseurl . '/events/view/' . $element['Event']['id']),
                    h($element['Event']['id']),
                    h($element['Event']['info'])
                );
            } else {
                echo $this->element(
                    '/genericElementsBS5/IndexTable/Fields/uuid',
                    [
                        'row' => $row,
                        'field' => [
                            'data_path' => 'element_uuid',
                            'url' => $baseurl . '/events/view/%id%',
                        ]
                    ]
                );
            }
            }
            else if($element['element_type'] === "GalaxyCluster") {
                if (!empty($element['GalaxyCluster'])) {
                    echo $this->element(
                        '/genericElementsBS5/IndexTable/Fields/galaxy',
                        [
                            'row' => $row,
                            'field' => [
                                'data_path' => 'GalaxyCluster',
                            ]
                        ]
                    );
                } else {
                    echo $this->element(
                        '/genericElementsBS5/IndexTable/Fields/uuid',
                        [
                            'row' => $row,
                            'field' => [
                                'data_path' => 'element_uuid',
                                'url' => $baseurl . '/galaxy_clusters/view/%id%'
                            ]
                        ]
                    );
                }
            }
            else if (in_array($element['element_type'], ['Attribute', 'Object'], true)) {
                $isAttribute = $element['element_type'] === 'Attribute';
                $target = $element[$element['element_type']] ?? null;
                if (!empty($target)) {
                    printf(
                        '<a class="text-decoration-none d-inline-flex align-items-baseline gap-1 text-break" href="%s">'
                            . '<span class="badge %s">%s</span>'
                            . '<span class="text-body%s">%s</span>'
                        . '</a>',
                        h($baseurl . '/events/view/' . $target['event_id']),
                        $isAttribute ? 'bg-attribute' : 'bg-object',
                        h($isAttribute ? $target['type'] : $target['name']),
                        $isAttribute ? ' font-monospace' : '',
                        h($isAttribute ? $target['value'] : $target['meta-category'])
                    );
                    printf(
                        '<span class="text-muted small text-truncate flex-grow-1" style="flex-basis:0;min-width:0;">%s</span>',
                        h(__('in #%s %s', $target['event_id'], $target['Event']['info'] ?? ''))
                    );
                } else {
                    printf('<span class="fst-italic text-muted">%s</span>', h($element['element_uuid']));
                }
            }
            else if ($element['element_type'] === 'AttributeValue') {
                if (isset($element['AttributeValue']['value'])) {
                    printf(
                        '<a class="text-decoration-none text-break" href="%s">'
                            . '<span class="text-body font-monospace">%s</span>'
                        . '</a>',
                        h($baseurl . '/values/view/' . ValueUrlTool::address($element['AttributeValue']['value'])),
                        h($element['AttributeValue']['value'])
                    );
                } else {
                    printf(
                        '<span class="fst-italic text-muted text-break" title="%s">%s</span>',
                        h(__('This value could not be resolved, so it is shown by the SHA-256 of its text.')),
                        h($element['element_sha256'])
                    );
                }
            }
        ?>
    </div>

    <!-- Show if it contains a description -->
    <?php if (!empty($element['description'])): ?>
        <div class="card card-link-item bg-light">
            <div class="card-body p-1">
                <i class="fa fa-comment"></i> 
                <span><?= h($element['description']) ?></span>
            </div>
        </div>
    <?php endif; ?>

</div>