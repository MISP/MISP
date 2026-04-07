<?php
$element = Hash::extract($row, $field['data_path']);

if (empty($element)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex flex-column gap-1">
    <div class="d-flex align-items-baseline gap-2 mb-0">
        <?php if($element['element_type'] === "Event") {
            echo $this->element(
                    '/genericElementsBS5/IndexTable/Fields/uuid',
                    [
                        'row' => $row,
                        'field' => [
                            'data_path' => 'element_uuid',
                            'url' => $baseurl . '/events/view2/%id%',
                        ]
                    ]
                );
            }
            else if($element['element_type'] === "GalaxyCluster") {
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
        ?>
    </div>

    <!-- Show if it contains a description -->
    <?php if (!empty($element['description'])): ?>
        <div class="card card-link-item" style="background-color: #f8f9fa;">
            <div class="card-body p-1">
                <i class="fa fa-comment"></i> 
                <span><?= h($element['description']) ?></span>
            </div>
        </div>
    <?php endif; ?>

</div>