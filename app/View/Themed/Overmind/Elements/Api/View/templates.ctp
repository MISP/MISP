<?php
$first = true;
foreach ($allAccessibleApis as $category => $actions):
    $groupId = 'rest-templates-' . $category;
    $label = Inflector::humanize($category);
?>
    <div data-rest-group>
        <button type="button"
                class="btn btn-sm w-100 d-flex align-items-center gap-2 border-0 fw-semibold text-start px-2 rest-group-toggle<?= $first ? '' : ' collapsed' ?>"
                data-bs-toggle="collapse" data-bs-target="#<?= h($groupId) ?>"
                aria-expanded="<?= $first ? 'true' : 'false' ?>" aria-controls="<?= h($groupId) ?>">
            <i class="fas fa-chevron-<?= $first ? 'down' : 'right' ?> fa-fw fa-xs text-body-tertiary" data-rest-chevron></i>
            <span class="flex-grow-1 text-truncate"><?= h($label) ?></span>
            <span class="badge rounded-pill bg-body-secondary text-body-secondary" data-rest-group-count><?= count($actions) ?></span>
        </button>
        <div class="collapse<?= $first ? ' show' : '' ?>" id="<?= h($groupId) ?>">
            <div class="d-flex flex-column gap-1 ps-3 pb-2">
                <?php foreach ($actions as $action => $api): ?>
                    <?= $this->element('Api/View/endpoint_row', [
                        'kind' => 'template',
                        'url' => $api[0],
                        'method' => $api[1],
                        'filter' => $label . ' ' . $action,
                    ]) ?>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
<?php
    $first = false;
endforeach;
