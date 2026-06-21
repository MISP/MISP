<?php
$id = Hash::get($row, $field['data_path']);
if (empty($id) && !empty($row['id'])) {
    $id = $row['id'];
}
$actions  = $field['actions'] ?? [];
$seed     = mt_rand();
$tempboxId = 'TempBox-' . $seed;


if ($field['data_path'] === 'Event.id') {
    $mayModify  = $this->Acl->canModifyEvent($row);
    $canPublish = $this->Acl->canPublishEvent($row);
} elseif ($field['data_path'] === 'Attribute.id') {
    if (!isset($mayModify)){
        $mayModify = $this->Acl->canModifyEvent($row);
    }
} elseif ($field['data_path'] === 'Collection.id' || !empty($data['Collection'])) {
    if (!isset($mayModify)){
        $mayModify = $this->Acl->canModifyCollection($row);
    }
} elseif ($field['data_path'] === 'TagCollection.id') {
    if (!isset($mayModify)){
        $mayModify = $this->Acl->canModifyTagCollection($row);
    }
} elseif ($field['data_path'] === 'SharingGroup.id') {
    if (!isset($mayModify)){
        $mayModify = $row['editable'] ?? false;
    }
} else {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin ?? false;
}   }
?>

<div class="d-inline-flex align-items-center checkbox-actions-wrapper checkbox-index">
    <div class="dropdown">
        <button
            class="btn btn-sm btn-light p-1"
            type="button"
            data-bs-toggle="dropdown"
            aria-expanded="false">
            <i class="fa-solid fa-ellipsis-vertical fs-5"></i>
        </button>

        <ul class="dropdown-menu dropdown-menu-end shadow-sm">

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

                    <?php if ($action['type'] === 'navigate'): ?>
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
                                $url = str_replace(['%action%', '%id%'], [$state ? 'unpublish' : 'publish', $id], $url);
                            }

                            if ($action['label_on'] === "Disable"){
                                $state = Hash::get($row, $action['enable_path']);
                                $label = $state ? $action['label_on'] : $action['label_off'];
                                $iconClass = $state ? $action['icon_on'] : $action['icon_off'];
                                $url = str_replace(['%action%', '%id%'], ['toggleEnable', $id], $url);
                            }

                            if ($action['label_on'] === "Optional"){
                                $state = Hash::get($row, $action['require_path']);
                                $label = $state ? $action['label_on'] : $action['label_off'];
                                $iconClass = $state ? $action['icon_on'] : $action['icon_off'];
                                $url = str_replace(['%action%', '%id%'], ['toggleRequired', $id], $url);
                            }

                            if ($action['label_on'] === "Remove Highlight"){
                                $state = Hash::get($row, $action['highlight_path']);
                                $label = $state ? $action['label_on'] : $action['label_off'];
                                $iconClass = $state ? $action['icon_on'] : $action['icon_off'];
                                $url = str_replace(['%action%', '%id%'], ['toggleHighlighted', $id], $url);
                            }

                            if ($action['label_on'] === "Deactivate"){
                                $state = Hash::get($row, $action['active_path']);
                                $label = $state ? $action['label_on'] : $action['label_off'];
                                $iconClass = $state ? $action['icon_on'] : $action['icon_off'];
                                $url = str_replace(['%action%', '%id%'], ['toggleActive', $id], $url);
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

                    <?php elseif ($action['type'] === 'modal'): ?>
                        <?php
                        $classes = 'dropdown-item ' . ($action['class'] ?? '');
                        if (!empty($action['size'])) {
                            $onclick = "event.preventDefault(); openModal('$url', '" . $action['size'] . "');";
                        } elseif ($action['label'] === __('Delete') || $action['label'] === __('Soft Delete') || $action['label'] === __('Restore')) {
                            $onclick = "event.preventDefault(); openModal('$url', 'sm');";
                        } else {
                            $onclick = "event.preventDefault(); openModal('$url');";
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
