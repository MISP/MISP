<?php $menuEndClass = !empty($alignEnd) ? ' dropdown-menu-end' : ''; ?>
<?php
    // Stable hook for the onboarding tour, which spotlights the top-level
    // menus by name (nav-datapoints, nav-account, …).
    $tourAttr = empty($item['id'])
        ? ''
        : ' data-tour="nav-' . h($item['id']) . '"';
?>
<?php if (!empty($item['children'])): ?>
    <li class="nav-item dropdown"<?= $tourAttr ?>>
        <a class="nav-link dropdown-toggle <?= !empty($item['active']) ? 'active' : '' ?>" href="#" data-bs-toggle="dropdown">
            <?= $this->element('navbar_item', ['item' => $item]) ?>
            <i class="menu-arrow fas"></i>
        </a>
        <ul class="dropdown-menu<?= $menuEndClass ?>">
            <?php foreach ($item['children'] as $child): ?>
                <?php if (!empty($child['divider'])): ?>
                    <li><hr class="dropdown-divider"></li>
                    <?php continue; ?>
                <?php endif; ?>
                <?php if (!empty($child['children'])): ?>
                    <li class="nav-item dropdown-submenu">
                        <a class="dropdown-item" href="#" data-bs-toggle="dropdown">
                            <?= $this->element('navbar_item', ['item' => $child]) ?>
                            <i class="menu-arrow fas fa-chevron-right"></i>
                        </a>
                        <ul class="dropdown-menu">
                            <?php foreach ($child['children'] as $sub): ?>
                                <?php if (!empty($sub['type']) && $sub['type'] === 'theme'): ?>
                                    <li>
                                        <a class="dropdown-item setTheme text-wrap"
                                           href="#"
                                           data-url="<?= $baseurl ?>/users/setTheme/<?= h($sub['theme']) ?>"
                                           data-theme="<?= h($sub['theme']) ?>">
                                            <div class="d-flex flex-column">
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <div>
                                                        <i class="fas fa-desktop fa-fw"></i>
                                                        <?= h($sub['label']) ?>
                                                    </div>
                                                    <span class="badge <?= $sub['on'] ? 'bg-success' : 'bg-secondary' ?> ms-2">
                                                        <?= $sub['on'] ? 'ON' : 'OFF' ?>
                                                    </span>
                                                </div>
                                                <?php if (!empty($sub['description'])): ?>
                                                    <div class="small text-muted"><?= h($sub['description']) ?></div>
                                                <?php endif; ?>
                                            </div>
                                        </a>
                                    </li>
                                <?php elseif (!empty($sub['type']) && $sub['type'] === 'message'): ?>
                                    <li class="dropdown-item-text text-warning">
                                        <i class="fas fa-exclamation-triangle"></i>
                                        <?= h($sub['label']) ?>
                                        <?php if (!empty($sub['description'])): ?>
                                            <div class="small text-muted"><?= h($sub['description']) ?></div>
                                        <?php endif; ?>
                                    </li>
                                <?php else: ?>
                                    <li>
                                        <a class="dropdown-item" href="<?= h($sub['url']) ?>">
                                            <?= $this->element('navbar_item', ['item' => $sub]) ?>
                                        </a>
                                    </li>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </ul>
                    </li>
                <?php elseif (!empty($child['type']) && $child['type'] === 'darkMode'): ?>
                    <li>
                        <a class="dropdown-item toggle-dark-mode" href="#">
                            <div class="d-flex justify-content-between align-items-center w-100">
                                <div>
                                    <i class="<?= h($child['icon']) ?> fa-fw dark-mode-icon"></i>
                                    <span><?= h($child['label']) ?></span>
                                </div>
                                <span class="badge bg-secondary dark-mode-badge ms-2">OFF</span>
                            </div>
                        </a>
                    </li>
                <?php elseif (!empty($child['type']) && $child['type'] === 'tutorial'): ?>
                    <li>
                        <a class="dropdown-item onboarding-launch" href="#">
                            <?= $this->element('navbar_item', ['item' => $child]) ?>
                        </a>
                    </li>
                <?php elseif (!empty($child['type']) && $child['type'] === 'setHomepage'): ?>
                    <li>
                        <a class="dropdown-item set-homepage" href="#">
                            <?= $this->element('navbar_item', ['item' => $child]) ?>
                        </a>
                    </li>
                <?php else: ?>
                    <li>
                        <a class="dropdown-item" href="<?= h($child['url']) ?>">
                            <?= $this->element('navbar_item', ['item' => $child]) ?>
                        </a>
                    </li>
                <?php endif; ?>
            <?php endforeach; ?>
        </ul>
    </li>
<?php else: ?>
    <li class="nav-item">
        <a class="nav-link" href="<?= h($item['url']) ?>">
            <?= $this->element('navbar_item', ['item' => $item]) ?>
        </a>
    </li>
<?php endif; ?>
