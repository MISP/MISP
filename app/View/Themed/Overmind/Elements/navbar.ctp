<nav class="navbar navbar-expand-xl navbar-dark bg-dark fixed-top shadow-sm">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="<?= empty($homepage['path']) ? $baseurl .'/' : $baseurl . h($homepage['path']) ?>">
            <?= $this->Html->image('misp-logo-main-cmyk-icon coul.png', ['alt' => __('MISP Logo'), 'class' => 'navbar-logo']) ?>
        </a>

        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNavbar">
            <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse justify-content-between" id="mainNavbar">
            <ul class="navbar-nav mb-lg-0">
                <?php foreach ($menus['left'] as $item): ?>
                    <!-- Look if the menu have sections -->
                    <?php if (!empty($item['children'])): ?>
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle <?= !empty($item['active']) ? 'active' : '' ?>" href="#" data-bs-toggle="dropdown">
                                <?= $this->element('navbar_item', ['item' => $item]) ?> <!-- Print menu name -->
                                <i class="menu-arrow fas"></i>
                            </a>
                            <ul class="dropdown-menu">
                                <?php foreach ($item['children'] as $child): ?>
                                    <?php if (!empty($child['divider'])): ?>
                                        <li><hr class="dropdown-divider"></li>
                                        <?php continue; ?>
                                    <?php endif; ?>
                                    <!-- Look if a section have subsections -->
                                    <?php if (!empty($child['children'])): ?>
                                        <li class="nav-item dropdown-submenu">
                                            <a class="dropdown-item" href="#" data-bs-toggle="dropdown">
                                                <?= $this->element('navbar_item', ['item' => $child]) ?> <!-- Print section name -->
                                                <i class="menu-arrow fas fa-chevron-right"></i>
                                            </a>
                                            <ul class="dropdown-menu">
                                                <?php foreach ($child['children'] as $sub): ?>
                                                    <li>
                                                        <a class="dropdown-item" href="<?= h($sub['url']) ?>">
                                                            <?= $this->element('navbar_item', ['item' => $sub]) ?> <!-- Print subsection name -->
                                                        </a>
                                                    </li>
                                                <?php endforeach; ?>
                                            </ul>
                                        </li>
                                    <?php else: ?>
                                        <li>
                                            <a class="dropdown-item" href="<?= h($child['url']) ?>">
                                                <?= $this->element('navbar_item', ['item' => $child]) ?> <!-- Print section name (if it doesn't have children)-->
                                            </a>
                                        </li>
                                    <?php endif; ?>

                                <?php endforeach; ?>
                            </ul>
                        </li>
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="<?= h($item['url']) ?>">
                                <?= $this->element('navbar_item', ['item' => $item]) ?> <!-- Print menu name (if it doesn't have children)-->
                            </a>
                        </li>
                    <?php endif; ?>

                <?php endforeach; ?>
            </ul>

            <ul class="navbar-nav mb-lg-0">
                <?php foreach ($menus['right'] as $item): ?>
                    <!-- Look if the menu have sections -->
                    <?php if (!empty($item['children'])): ?>
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle <?= !empty($item['active']) ? 'active' : '' ?>" href="#" data-bs-toggle="dropdown">
                                <?= $this->element('navbar_item', ['item' => $item]) ?> <!-- Print menu name -->
                                <i class="menu-arrow fas"></i>
                            </a>
                            <ul class="dropdown-menu dropdown-menu-end">
                                <?php foreach ($item['children'] as $child): ?>
                                    <?php if (!empty($child['divider'])): ?>
                                        <li><hr class="dropdown-divider"></li>
                                        <?php continue; ?>
                                    <?php endif; ?>
                                    <!-- Look if a section have subsections -->
                                    <?php if (!empty($child['children'])): ?>
                                        <li class="nav-item dropdown-submenu">
                                            <a class="dropdown-item" href="#" data-bs-toggle="dropdown">
                                                <?= $this->element('navbar_item', ['item' => $child]) ?> <!-- Print section name -->
                                                <i class="menu-arrow fas fa-chevron-right"></i>
                                            </a>
                                            <ul class="dropdown-menu">
                                                <?php foreach ($child['children'] as $sub): ?>
                                                    <li>
                                                        <a class="dropdown-item" href="<?= h($sub['url']) ?>">
                                                            <?= $this->element('navbar_item', ['item' => $sub]) ?> <!-- Print subsection name -->
                                                        </a>
                                                    </li>
                                                <?php endforeach; ?>
                                            </ul>
                                        </li>
                                    <?php else: ?>
                                        <li>
                                            <a class="dropdown-item" href="<?= h($child['url']) ?>">
                                                <?= $this->element('navbar_item', ['item' => $child]) ?> <!-- Print section name (if it doesn't have children)-->
                                            </a>
                                        </li>
                                    <?php endif; ?>

                                <?php endforeach; ?>
                            </ul>
                        </li>
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="<?= h($item['url']) ?>">
                                <?= $this->element('navbar_item', ['item' => $item]) ?> <!-- Print menu name (if it doesn't have children)-->
                            </a>
                        </li>
                    <?php endif; ?>

                <?php endforeach; ?>
            </ul>
        </div>
    </div>
</nav>
