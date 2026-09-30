<?php
/*
 * A detail page split into tabs, each a left column and an optional right one.
 *
 *   $data  array  the entity, passed to every element
 *   $tabs  array  one entry per tab:
 *     id           string  anchor, the pane is #tab-<id>
 *     title        string  the tab label
 *     icon         string  full class attribute of the label glyph
 *     count        int     shown after the label
 *     active       bool    open this tab first (default: the first one)
 *     description  string  the page header's description while this tab is
 *                          open; a tab without one shows the page's own
 *                          `headerDescription`
 *     heading      string  sets the page's headerTitle
 *     left, right  array   element paths, ['element' => path] or
 *                          ['ajax' => url] for a lazy fragment
 *
 * Like an action declared with 'tab', the per-tab descriptions are all
 * rendered in the header and toggled by syncHeaderActions() below.
 */
$tabDescriptions = [];
foreach ($tabs as $tab) {
    if (!empty($tab['description'])) {
        $tabDescriptions[$tab['id']] = $tab['description'];
    }
}
if (!empty($tabDescriptions)) {
    $pageDescription = $this->get('headerDescription');
    if (is_array($pageDescription)) {
        $tabDescriptions += $pageDescription;
    } else {
        $tabDescriptions[''] = $pageDescription;
    }
    $this->set('headerDescription', $tabDescriptions);
}

$activeTabIndex = 0;
foreach ($tabs as $i => $tab) {
    if (!empty($tab['active'])) {
        $activeTabIndex = $i;
        break;
    }
}
?>

<div class="container-fluid">
    <ul class="nav nav-tabs mb-3 fs-5" role="tablist" data-tour="view-tabs">
        <?php foreach ($tabs as $i => $tab): ?>
            <?php $isActive = $i === $activeTabIndex; ?>
            <li class="nav-item"  role="presentation">
                <a class="nav-view nav-link d-flex align-items-center gap-2 bg-light text-dark <?= $isActive ? 'active' : '' ?>"
                    data-tour="view-tab-<?= h($tab['id']) ?>"
                    data-bs-toggle="tab"
                    href="#tab-<?= h($tab['id']) ?>"
                    role="tab"
                    aria-selected="<?= $isActive ? 'true' : 'false' ?>">

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
            <div class="tab-pane fade <?= $i === $activeTabIndex ? 'show active' : '' ?>"
                id="tab-<?= h($tab['id']) ?>"
                role="tabpanel">
                <?php if (!empty($tab['heading'])){
                        $this->set('headerTitle', $tab['heading']);
                    }
                ?>
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

// The header strip is rendered once by the page and never re-rendered on tab
// switch, so header actions and descriptions tagged with data-header-tab are
// toggled here to match the active tab. Untagged ones are left untouched; a
// data-header-tab-fallback description shows while no sibling claims the tab.
function syncHeaderActions(tabId) {
    document.querySelectorAll('[data-header-tab]').forEach(function (el) {
        el.classList.toggle('d-none', el.getAttribute('data-header-tab') !== tabId);
    });
    document.querySelectorAll('[data-header-tab-fallback]').forEach(function (el) {
        var claimed = Array.prototype.some.call(el.parentNode.children, function (sibling) {
            return sibling.getAttribute('data-header-tab') === tabId;
        });
        el.classList.toggle('d-none', claimed);
    });
}

function currentTabId() {
    var active = document.querySelector('.nav-view.active[href^="#tab-"]');
    return active ? active.getAttribute('href').replace('#tab-', '') : null;
}

document.addEventListener('DOMContentLoaded', function () {
    // Restore active tab from URL hash on load
    activateTabFromHash();

    // Reveal the header actions belonging to the initially active tab
    syncHeaderActions(currentTabId());

    // Keep URL hash + header actions in sync when switching tabs
    document.querySelectorAll('.nav-link[data-bs-toggle="tab"]').forEach(function (tab) {
        tab.addEventListener('shown.bs.tab', function (e) {
            var href = e.target.getAttribute('href');
            if (href) {
                history.replaceState(null, '', href);
                syncHeaderActions(href.replace('#tab-', ''));
            }
        });
    });
});

// Activate tab when hash changes without page reload (same-page anchor links)
window.addEventListener('hashchange', function () {
    activateTabFromHash();
    syncHeaderActions(currentTabId());
});
</script>