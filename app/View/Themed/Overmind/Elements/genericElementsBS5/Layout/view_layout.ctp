<div class="container-fluid">
    <ul class="nav nav-tabs mb-3 fs-5" role="tablist">
        <?php foreach ($tabs as $i => $tab): ?>
            <li class="nav-item"  role="presentation">
                <a class="nav-view nav-link d-flex align-items-center gap-2 bg-light text-dark <?= $i === 0 ? 'active' : '' ?>"
                    data-bs-toggle="tab"
                    href="#tab-<?= h($tab['id']) ?>"
                    role="tab"
                    aria-selected="<?= $i === 0 ? 'true' : 'false' ?>">

                    <?php if (!empty($tab['icon'])): ?>
                        <i class="<?= h($tab['icon']) ?>"></i>
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

<script>
function activateTabFromHash() {
    var hash = window.location.hash;
    if (!hash) return;
    var target = document.querySelector('.nav-link[href="' + hash + '"]');
    if (target) bootstrap.Tab.getOrCreateInstance(target).show();
}

document.addEventListener('DOMContentLoaded', function () {
    // Restore active tab from URL hash on load
    activateTabFromHash();

    // Keep URL hash in sync when switching tabs
    document.querySelectorAll('.nav-link[data-bs-toggle="tab"]').forEach(function (tab) {
        tab.addEventListener('shown.bs.tab', function (e) {
            var href = e.target.getAttribute('href');
            if (href) history.replaceState(null, '', href);
        });
    });
});

// Activate tab when hash changes without page reload (same-page anchor links)
window.addEventListener('hashchange', activateTabFromHash);
</script>