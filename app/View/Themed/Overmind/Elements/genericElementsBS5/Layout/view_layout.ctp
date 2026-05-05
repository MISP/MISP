<div class="container-fluid mt-3">
    <h2 class="mb-3">
        <?php if (!empty($title)): ?>
            <?= h($title) ?>
        <?php endif; ?>
    </h2>
    <ul class="nav nav-tabs mb-3 fs-5" role="tablist">
        <?php foreach ($tabs as $i => $tab): ?>
            <li class="nav-item"  role="presentation">
                <a class="nav-view nav-link d-flex align-items-center gap-2 <?= $i === 0 ? 'active' : '' ?>"
                    data-bs-toggle="tab"
                    href="#tab-<?= h($tab['id']) ?>"
                    role="tab"
                    aria-selected="<?= $i === 0 ? 'true' : 'false' ?>">

                    <?php if (!empty($tab['icon'])): ?>
                        <i class="fas fa-<?= h($tab['icon']) ?>"></i>
                    <?php endif; ?>

                    <?php if (!empty($tab['title'])): ?>
                        <?= h($tab['title']) ?>
                    <?php endif; ?>

                    <?php if (!empty($tab['count'])): ?>
                        <span> (<?= h($tab['count']) ?>) </span>
                    <?php endif; ?>
                </a>
            </li>
        <?php endforeach; ?>
    </ul>

    <div class="tab-content">
        <?php foreach ($tabs as $i => $tab): ?>
            <div class="tab-pane fade <?= $i === 0 ? 'show active' : '' ?>"
                id="tab-<?= h($tab['id']) ?>"
                role="tabpanel">
                <div class="row">
                    <!-- LEFT COLUMN -->
                    <div class="<?= !empty($tab['right']) ? 'col-lg-9' : 'col-12' ?>">
                        <?php
                            if (!empty($tab['left'])) {
                                foreach ($tab['left'] as $card) {
                                    if (is_array($card)) {

                                        if (!empty($card['ajax'])) {
                                            echo '<div class="ajax-tab-content" data-url="' . h($card['ajax']) . '">';
                                            echo '<div class="text-center p-4">';
                                            echo '<div class="spinner-border"></div>';
                                            echo '</div>';
                                            echo '</div>';
                                        } elseif (!empty($card['element'])) {
                                            echo $this->element($card['element'], ['data' => $data]);
                                        }

                                    } else {
                                        echo $this->element($card, ['data' => $data]);
                                    }
                                }
                            }
                        ?>
                    </div>
                    <?php if (!empty($tab['right'])): ?>
                        <!-- RIGHT COLUMN -->
                        <div class="col-lg-3">
                            <?php
                                foreach ($tab['right'] as $card) {
                                    if (is_array($card)) {

                                        if (!empty($card['ajax'])) {
                                            echo '<div class="ajax-card" data-url="' . h($card['ajax']) . '">';
                                            echo '<div class="text-center p-4">';
                                            echo '<div class="spinner-border"></div>';
                                            echo '</div>';
                                            echo '</div>';
                                        } elseif (!empty($card['element'])) {
                                            echo $this->element($card['element'], ['data' => $data]);
                                        }

                                    } else {
                                        echo $this->element($card, ['data' => $data]);
                                    }
                                }
                            ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</div>