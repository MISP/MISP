<?php
/**
 * What a lazily-loaded card shows before its fetch answers.
 *
 * The default is a centred spinner, which says *something is coming*
 * and nothing else: the container is ~84px tall whatever will land in
 * it, so a tab of them opens as a row of spinners and then grows panel
 * by panel as the fetches return. A caller that knows the shape of what
 * it asked for can pass `placeholder` — an element and its params — and
 * draw that shape instead, so the page has its structure and its
 * section names from the first paint.
 *
 * `Layout/ajax_card_skeleton` beside this file is the ready-made one,
 * and its docblock has the call:
 *
 * ```php
 * $card['placeholder'] = array(
 *     'element' => 'genericElementsBS5/Layout/ajax_card_skeleton',
 *     'params' => array('cards' => array(
 *         array('title' => __('Attributes'), 'icon' => 'fas fa-tag',
 *               'lines' => 8),
 *     )),
 * );
 * ```
 *
 * @param array $card
 * @return void
 */
$ajaxPlaceholder = function (array $card) {
    if (!empty($card['placeholder']['element'])) {
        echo $this->element(
            $card['placeholder']['element'],
            $card['placeholder']['params'] ?? array()
        );
        return;
    }
    echo '<div class="p-4">';
    echo $this->element('genericElementsBS5/loader');
    echo '</div>';
};

/**
 * One card in a column, in whichever of the three shapes a caller uses.
 *
 * Extracted because both columns had the same body, and because the row
 * group below needs a third caller for it. `$containerClass` is the only
 * thing the two columns ever differed by: the left emits
 * `.ajax-tab-content` and the right rail `.ajax-card`, and
 * `AJAX_CONTAINER_SELECTOR` in mispOvermind.js matches both.
 *
 * @param mixed $card An array with `ajax`, with `element`, or a plain
 *                    element name
 * @param string $containerClass
 * @return void
 */
$renderCard = function ($card, $containerClass) use ($ajaxPlaceholder, $data) {
    if (!is_array($card)) {
        echo $this->element($card, array('data' => $data));
        return;
    }
    if (!empty($card['ajax'])) {
        // Optional `id` gives a lazily-loaded panel an anchor a link can
        // reach before its content has arrived. Absent for every
        // existing caller.
        // Optional `share`: the same URL on several tabs is fetched once.
        echo '<div class="' . h($containerClass) . '"'
            . (empty($card['id']) ? '' : ' id="' . h($card['id']) . '"')
            . (empty($card['share']) ? '' : ' data-share="1"')
            . ' data-url="' . h($card['ajax']) . '">';
        $ajaxPlaceholder($card);
        echo '</div>';
        return;
    }
    if (!empty($card['element'])) {
        // Optional `params` lets one element serve several cards. Absent
        // for every existing caller, so their render is unchanged.
        echo $this->element(
            $card['element'],
            array('data' => $data) + ($card['params'] ?? array())
        );
    }
};

/**
 * A group of cards that sit beside each other instead of stacking.
 *
 * `array('row' => array($cardA, $cardB))` in a column's list, where the
 * default is one card per row at full width. Absent for every existing
 * caller, so nothing that does not ask for it changes.
 *
 * **It is an `xl` split, so the row is a large-screen arrangement
 * only.** Below the breakpoint the columns stack and the panels are
 * exactly what they were — which is the point: two panels side by side
 * is a claim about horizontal room, and a narrow window does not have
 * any. Bootstrap's own `.row` does the stacking; nothing here is
 * conditional.
 *
 * Cards share the width evenly unless one names its own `col`, and a
 * card that renders nothing leaves no empty column. Each cell is a flex
 * column, so a card that grows fills the row's height.
 *
 * @param array $group The `row` value
 * @param string $containerClass As $renderCard
 * @return void
 */
$renderRow = function (array $group, $containerClass) use ($renderCard) {
    $cells = array();
    foreach (array_filter($group) as $card) {
        ob_start();
        $renderCard($card, $containerClass);
        $html = ob_get_clean();
        if (trim($html) !== '') {
            $cells[] = array($card, $html);
        }
    }
    if (empty($cells)) {
        return;
    }
    echo '<div class="row gx-3">';
    foreach ($cells as list($card, $html)) {
        $col = is_array($card) && !empty($card['col'])
            ? $card['col']
            : 'col-12 col-xl';
        echo '<div class="' . h($col) . ' d-flex flex-column">' . $html . '</div>';
    }
    echo '</div>';
};

/**
 * A column's whole list, stacking cards and laying out row groups.
 *
 * @param array $cards
 * @param string $containerClass As $renderCard
 * @return void
 */
$renderColumn = function ($cards, $containerClass) use (
    $renderCard, $renderRow
) {
    foreach ((array)$cards as $card) {
        if (is_array($card) && !empty($card['row'])) {
            $renderRow($card['row'], $containerClass);
            continue;
        }
        $renderCard($card, $containerClass);
    }
};

/*
 * A detail page split into tabs, each a left column and an optional right one.
 *
 *   $data  array  the entity, passed to every element
 *   $tabs  array  one entry per tab:
 *     id           string  anchor, the pane is #tab-<id>
 *     title        string  the tab label
 *     icon         string  full class attribute of the label glyph
 *     iconColor    string  CSS colour of the glyph; a misp-icon-<entity> icon
 *                          takes its entity colour without it
 *     count        int     shown after the label
 *     active       bool    open this tab first (default: the first one)
 *     description  string  the page header's description while this tab is
 *                          open; a tab without one shows the page's own
 *                          `headerDescription`
 *     heading      string  sets the page's headerTitle
 *     left, right  array   element paths, ['element' => path],
 *                          ['ajax' => url] for a lazy fragment, or
 *                          ['row' => [path, path]] for cards side by side
 *                          (stacked below xl, stretched to one height)
 *   $ownership  array  for a record with a creator org and a distribution:
 *                      Cards/ownership_card's parameters; the card opens the
 *                      first tab's left column
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

$entityIconColours = array(
    'event', 'object', 'attribute', 'tag', 'galaxy', 'report', 'sighting',
    'correlation', 'analystData', 'enrichment',
);
$tabIconColour = function (array $tab) use ($entityIconColours) {
    if (!empty($tab['iconColor'])) {
        return $tab['iconColor'];
    }
    $matched = preg_match(
        '/\bmisp-icon-([A-Za-z]+)\b/', $tab['icon'] ?? '', $m
    );
    if ($matched && in_array($m[1], $entityIconColours, true)) {
        return 'var(--bs-' . $m[1] . ')';
    }
    return null;
};
?>

<div class="container-fluid">
    <ul class="nav ov-view-tabs" role="tablist" data-tour="view-tabs">
        <?php foreach ($tabs as $i => $tab): ?>
            <?php
                $isActive = $i === $activeTabIndex;
                $iconColour = $tabIconColour($tab);
            ?>
            <li class="nav-item"  role="presentation">
                <a class="nav-view nav-link <?= $isActive ? 'active' : '' ?>"
                    data-tour="view-tab-<?= h($tab['id']) ?>"
                    data-bs-toggle="tab"
                    href="#tab-<?= h($tab['id']) ?>"
                    role="tab"
                    <?= $iconColour === null ? '' : 'style="--ov-view-tab-icon: ' . h($iconColour) . ';"' ?>
                    aria-selected="<?= $isActive ? 'true' : 'false' ?>">

                    <?php if (!empty($tab['icon'])): ?>
                        <i class="<?= h($tab['icon']) ?>"></i>
                    <?php endif; ?>

                    <?php if (!empty($tab['title'])): ?>
                        <span><?= h($tab['title']) ?></span>
                    <?php endif; ?>

                    <?php if (isset($tab['count'])): ?>
                        <span class="ov-tab-count" data-tab-count="<?= h($tab['id']) ?>"><?=
                            h(number_format((int)$tab['count']))
                        ?></span>
                    <?php endif; ?>

                    <?php
                    /*
                     * Optional state pill, for a tab whose content resolves to
                     * a state rather than to a count — a verdict, a status, a
                     * severity. `label` is required; `color` is any CSS colour
                     * (a variable is the intent) and `dot` prefixes a filled
                     * circle in it. Absent for every existing caller.
                     */
                    ?>
                    <?php if (!empty($tab['badge']['label'])): ?>
                        <span class="nav-view-badge"<?=
                            empty($tab['badge']['color'])
                                ? ''
                                : ' style="--nav-view-badge-color: '
                                    . h($tab['badge']['color']) . ';"'
                        ?>>
                            <?php if (!empty($tab['badge']['dot'])): ?>
                                <span class="nav-view-badge-dot"></span>
                            <?php endif; ?>
                            <?= h($tab['badge']['label']) ?>
                        </span>
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
                            if ($i === 0 && !empty($ownership)) {
                                echo $this->element('genericElementsBS5/Cards/ownership_card', $ownership);
                            }
                            if (!empty($tab['left'])) {
                                $renderColumn($tab['left'], 'ajax-tab-content');
                            }
                        ?>
                    </div>
                    <?php if (!empty($tab['right'])): ?>
                        <!-- RIGHT COLUMN -->
                        <div class="col-lg-3">
                            <?php $renderColumn($tab['right'], 'ajax-card'); ?>
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

function isViewTabsStuck(strip) {
    var top = parseFloat(getComputedStyle(strip).top) || 0;
    return window.scrollY > 0 && strip.getBoundingClientRect().top <= top + 0.5;
}

function syncViewTabsChrome() {
    var strip = document.querySelector('.ov-view-tabs');
    if (!strip) return;
    strip.classList.toggle('is-stuck', isViewTabsStuck(strip));
    strip.classList.toggle('is-overflowing',
        strip.scrollLeft + strip.clientWidth < strip.scrollWidth - 1);
}

// Switching tabs from a pinned strip would otherwise land mid-way down the
// new pane, at whatever depth the previous one had been scrolled to.
function scrollToPaneTop(strip) {
    if (!isViewTabsStuck(strip)) return;
    var stripBottom = strip.getBoundingClientRect().bottom;
    var marginBottom = parseFloat(getComputedStyle(strip).marginBottom) || 0;
    var pane = document.querySelector('.tab-content');
    var overshoot = stripBottom + marginBottom - pane.getBoundingClientRect().top;
    if (overshoot > 0) {
        window.scrollBy(0, -overshoot);
    }
}

window.addEventListener('scroll', syncViewTabsChrome, { passive: true });
window.addEventListener('resize', syncViewTabsChrome);

// A link to #tab-<id> from inside a panel has to switch tabs, not just move
// the hash. Bootstrap does not watch the hash, so neither did this.
window.addEventListener('hashchange', activateTabFromHash);

document.addEventListener('DOMContentLoaded', function () {
    // Restore active tab from URL hash on load
    activateTabFromHash();

    // Reveal the header actions belonging to the initially active tab
    syncHeaderActions(currentTabId());

    var strip = document.querySelector('.ov-view-tabs');
    if (strip) {
        strip.addEventListener('scroll', syncViewTabsChrome, { passive: true });
        var active = strip.querySelector('.nav-view.active');
        if (active) {
            strip.scrollLeft = active.parentNode.offsetLeft - strip.clientWidth / 3;
        }
        syncViewTabsChrome();
    }

    // Keep URL hash + header actions in sync when switching tabs
    document.querySelectorAll('.nav-link[data-bs-toggle="tab"]').forEach(function (tab) {
        tab.addEventListener('shown.bs.tab', function (e) {
            var href = e.target.getAttribute('href');
            if (href) {
                history.replaceState(null, '', href);
                syncHeaderActions(href.replace('#tab-', ''));
            }
        });
        if (strip) {
            tab.addEventListener('show.bs.tab', function () {
                scrollToPaneTop(strip);
            });
        }
    });
});

// Activate tab when hash changes without page reload (same-page anchor links)
window.addEventListener('hashchange', function () {
    activateTabFromHash();
    syncHeaderActions(currentTabId());
});
</script>