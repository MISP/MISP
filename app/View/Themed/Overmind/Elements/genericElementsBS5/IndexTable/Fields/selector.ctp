<?php
$id = Hash::get($row, $field['data_path']);
if(empty($id)){
    $id=$row['id'];
}
$actions = $field['actions'] ?? [];
$seed = mt_rand();
$tempboxId = 'TempBox-' . $seed;



$checkboxAttrs = [
    'type' => 'checkbox',
    'class' => 'item-checkbox form-check-input mass-select mt-0'
];

if (isset($field['state_path'])) {
    $checkboxAttrs['data-state'] = Hash::get($row, $field['state_path']) ? '1' : '0';
}

if ($field['data_path'] === 'Event.id') {
    $mayModify = $this->Acl->canModifyEvent($row);
    $canPublish = $this->Acl->canPublishEvent($row);
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Attribute.id') {
    if (!isset($mayModify)){
        $mayModify = $this->Acl->canModifyEvent($row);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Collection.id' || $field['data_path'] === 'id') {
    if (!isset($mayModify)){
        $mayModify = $this->Acl->canModifyCollection($row);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}


if ($field['data_path'] === 'Warninglist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Noticelist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Regexp.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Allowedlist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'CorrelationExclusion.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}
?>



<div class="d-inline-flex align-items-center checkbox-actions-wrapper checkbox-index">

    <!-- Checkbox -->
    <?= $this->Form->checkbox('selected_items[]', $checkboxAttrs); ?>

    <!-- Dropdown -->
    <div class="dropdown">
        <button 
            class="btn btn-sm btn-light dropdown-toggle p-1"
            type="button"
            data-bs-toggle="dropdown">
            <i class="fas fa-chevron-down"></i>
        </button>

        <ul class="dropdown-menu shadow-sm">

            <?php foreach ($actions as $action): ?>

                <?php
                $showAction = true;
                if (isset($action['requirement'])) {
                    if ($action['requirement'] === 'check_edit_rights') {
                        $showAction = $isSiteAdmin || $mayModify;
                    } else if ($action['requirement'] === 'check_publish_rights') {
                        $showAction = $isSiteAdmin || ($mayModify && $canPublish);
                    } else if ($action['requirement'] === 'check_site_admin') {
                        $showAction = $isSiteAdmin;
                    } else if ($action['requirement'] === 'check_edit_warninglists_rights') {
                        $showAction = $row['Warninglist']['default'] == 0 && ($me['Role']['perm_warninglist'] || $me['Role']['perm_site_admin']);
                    } else {
                        $showAction = (bool)$action['requirement'];
                    }
                }

                if (!$showAction) {
                    continue;
                }

                $url = str_replace('%id%', $id, $action['url']);
                ?>

                <li>

                    <?php if ($action['type'] === 'link'): ?>

                        <a class="dropdown-item" href="<?= h($url) ?>">
                            <div>
                                <i class="fas fa-<?= h($action['icon']) ?> me-2"></i>
                                <?= h($action['label']) ?>
                            </div>
                        </a>

                    <?php elseif ($action['type'] === 'toggle'): ?>
                        <?php
                            $state = Hash::get($row, $action['state_path']);
                            $label = $state ? $action['label_on'] : $action['label_off'];
                            $iconClass = $state ? $action['icon_on'] : $action['icon_off'];
                            $actionName = match($label) {
                                'Publish', 'Unpublish' => $state ? 'unpublish' : 'publish',
                                'Enable', 'Disable' => 'toggleEnable',
                                default => null,
                            };
                            $url = str_replace(['%action%', '%id%'], [$actionName, $id], $action['url']);
                        ?>
                        <?php if ($label === "Publish" || $label === "Unpublish"): ?>
                            <a class="dropdown-item" href="<?= h($url) ?>" onclick="event.preventDefault(); openModal('<?= h($url) ?>','sm');">
                                <div>
                                    <i class="fas fa-<?= $iconClass ?> me-2"></i>
                                    <?= h($label) ?>
                                </div>
                            </a>
                        <?php else: ?>
                            <?= $this->Form->postLink(
                                '<div><i class="fas fa-' . h($iconClass) . ' me-2"></i>' . h($label) . '</div>',
                                $url,
                                [
                                    'escape' => false,
                                    'class' => 'dropdown-item'
                                ]
                            ) ?>
                        <?php endif; ?>

                    <?php elseif ($action['type'] === 'ajax'): ?>
                        <?php
                        $url = str_replace('%id%', $id, $action['url']);
                        $classes = 'dropdown-item ' . ($action['class'] ?? '');
                        if ($action['label'] ===  __('Delete')){
                            $onclick="event.preventDefault(); openModal('$url', 'sm');";
                        } else {
                            $onclick="event.preventDefault(); openModal('$url');";
                        }
                        ?>

                        <a class="<?= trim($classes) ?>"
                        href="<?= h($url) ?>"
                        onclick="<?= h($onclick) ?>">
                            <div>
                                <i class="fas fa-<?= h($action['icon']) ?> me-2"></i>
                                <?= h($action['label']) ?>
                            </div>
                        </a>

                    <?php elseif ($action['type'] === 'divider'): ?>
                        <li><hr class="dropdown-divider"></li>

                    <?php endif; ?>

                </li>

            <?php endforeach; ?>

        </ul>
    </div>

    <span id="<?= $tempboxId ?>" class="d-none"></span>
</div>