<?php

$id = Hash::get($row, $field['data_path']);
if(empty($id)){
    if(!empty($row['id'])){
        $id=$row['id'];
    }
}
$actions = $field['actions'] ?? [];
$seed = mt_rand();
$tempboxId = 'TempBox-' . $seed;



$checkboxAttrs = [
    'type' => 'checkbox',
    'class' => 'item-checkbox form-check-input mass-select mt-0'
];

if (isset($field['publish_path'])) {
    $checkboxAttrs['data-publish'] = Hash::get($row, $field['publish_path']) ? '1' : '0';
}

if (isset($field['enable_path'])) {
    $checkboxAttrs['data-enable'] = Hash::get($row, $field['enable_path']) ? '1' : '0';
}

if (isset($field['require_path'])) {
    $checkboxAttrs['data-require'] = Hash::get($row, $field['require_path']) ? '1' : '0';
}

if (isset($field['highlight_path'])) {
    $checkboxAttrs['data-highlight'] = Hash::get($row, $field['highlight_path']) ? '1' : '0';
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

if ($field['data_path'] === 'Tag.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'TagCollection.id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $this->Acl->canModifyTagCollection($row);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Taxonomy.id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'existing_tag.Tag.id') {
    $checkboxAttrs['disabled'] = true;
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
                    if (is_callable($action['requirement'])) {
                        $showAction = call_user_func($action['requirement'], $row);
                    } else if ($action['requirement'] === 'check_edit_rights') {
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

                $url = $action['url'];
                $url = str_replace('%id%', $id, $url);
                if (!empty($action['url_params_data_paths'])) {
                    foreach ($action['url_params_data_paths'] as $placeholder => $path) {
                        $val = Hash::get($row, $path);
                        $url = str_replace('%' . $placeholder . '%', $val, $url);
                    }
                }
                ?>

                <li>

                    <?php if ($action['type'] === 'link'): ?>
                        <?php if (!empty($action['download'])): ?>
                            <a class="dropdown-item" href="<?= h($url) ?>" download="<?= h($title_for_layout) . h($id) . '.json' ?>">
                                <div>
                                    <i class="fas fa-<?= h($action['icon']) ?> me-2"></i>
                                    <?= h($action['label']) ?>
                                </div>
                            </a>
                        <?php else: ?>
                            <a class="dropdown-item" href="<?= h($url) ?>">
                                <div>
                                    <i class="fas fa-<?= h($action['icon']) ?> me-2"></i>
                                    <?= h($action['label']) ?>
                                </div>
                            </a>
                        <?php endif; ?>
                    <?php elseif ($action['type'] === 'toggle'): ?>
                        <?php
                            if ($action['label_on'] === "Unpublish"){
                                $state = Hash::get($row, $action['publish_path']);
                                $label = $state ? $action['label_on'] : $action['label_off'];
                                $iconClass = $state ? $action['icon_on'] : $action['icon_off'];
                                $url = str_replace(['%action%', '%id%'], [$state ? 'unpublish' : 'publish', $id], $action['url']);
                            }

                            if ($action['label_on'] === "Disable"){
                                $state = Hash::get($row, $action['enable_path']);
                                $label = $state ? $action['label_on'] : $action['label_off'];
                                $iconClass = $state ? $action['icon_on'] : $action['icon_off'];
                                $url = str_replace(['%action%', '%id%'], ['toggleEnable', $id], $action['url']);
                            }

                            if ($action['label_on'] === "Optional"){
                                $state = Hash::get($row, $action['require_path']);
                                $label = $state ? $action['label_on'] : $action['label_off'];
                                $iconClass = $state ? $action['icon_on'] : $action['icon_off'];
                                $url = str_replace(['%action%', '%id%'], ['toggleRequired', $id], $action['url']);
                            }

                            if ($action['label_on'] === "Remove Highlight"){
                                $state = Hash::get($row, $action['highlight_path']);
                                $label = $state ? $action['label_on'] : $action['label_off'];
                                $iconClass = $state ? $action['icon_on'] : $action['icon_off'];
                                $url = str_replace(['%action%', '%id%'], ['toggleHighlighted', $id], $action['url']);
                            }
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