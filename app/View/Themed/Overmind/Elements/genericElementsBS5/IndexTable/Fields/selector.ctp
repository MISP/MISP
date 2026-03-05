<?php
$id = Hash::get($row, $field['data_path']);
$actions = $field['actions'] ?? [];
$seed = mt_rand();
$tempboxId = 'TempBox-' . $seed;

$mayModify = $this->Acl->canModifyEvent($row);
$canPublish = $this->Acl->canPublishEvent($row);
?>

<div class="d-inline-flex align-items-center checkbox-actions-wrapper">

    <!-- Checkbox -->
    <input 
        type="checkbox"
        class="event-checkbox form-check-input select_attribute mt-0"
        data-event-id="<?= h($id) ?>"
        data-can-delete="<?= $mayModify ? '1' : '0' ?>"
    >

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
                            $actionName = $state ? 'unpublish' : 'publish';
                            $url = str_replace(['%action%', '%id%'], [$actionName, $id], $action['url']);
                        ?>

                        <a class="dropdown-item" href="<?= h($url) ?>" onclick="event.preventDefault(); openPublishModal('<?= h($url) ?>');">
                            <div>
                                <i class="fas fa-<?= $iconClass ?> me-2"></i>
                                <?= h($label) ?>
                            </div>
                        </a>

                    <?php elseif ($action['type'] === 'ajax'): ?>
                        <?php
                        $url = str_replace('%id%', $id, $action['url']);
                        $classes = 'dropdown-item ' . ($action['class'] ?? '');
                        ?>

                        <a class="<?= trim($classes) ?>"
                        href="<?= h($url) ?>"
                        onclick="event.preventDefault(); openDeleteModal('<?= h($url) ?>');">
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