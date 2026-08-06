<?php
$breadcrumb = '';
$unclickableControllers = ['pages'];
if (!empty($currentController)) {
    if ($currentController === 'galaxy_clusters') {
        $currentController = 'galaxies';
        $middle = 'clusters';
    }
    $controllerUrl = $this->Html->url('/' . $currentController);
    if ($currentController === 'users') {
        if (!empty($me['Role']['perm_site_admin'])) {
            $controllerUrl = $this->Html->url('/admin/' . $currentController);
        } else {
            $controllerUrl = $this->Html->url('#');
        }
    }
    if (in_array($currentController, $unclickableControllers)) {
        $controllerUrl = '#';
    }
    $breadcrumb = '<a href="' . $controllerUrl . '" '
        . 'class="text-muted text-decoration-none breadcrumb-controller-link">'
        . ucfirst(h($currentController)) . '</a>';
    if (!empty($currentAction)) {
        if (empty($middle)) {
            $breadcrumb .= ' > ' . ucfirst(h($currentAction));
        } else {
            $breadcrumb .= ' > ' . ucfirst(h($middle)) .  ' > ' . ucfirst(h($currentAction));
        }
    }
}

// `headerTitleHtml` lets a view supply pre-built, already-escaped title markup
$title = isset($headerTitleHtml)
    ? $headerTitleHtml
    : (isset($headerTitle)
        ? h($headerTitle)
        : (isset($currentController) ? ucfirst(h($currentController)) : ''));

$paginatorCount = null;
try {
    $paginatorParams = $this->Paginator->params();
    if (isset($paginatorParams['count'])) {
        $paginatorCount = (int)$paginatorParams['count'];
    }
} catch (Exception $e) {
    // no paginator on this page
}
$totalCount = $headerCount ?? $paginatorCount;

// Compact count formatting (1,4K, ...)
// Count prefixed with "+" to denote an estimate.
$abbreviateCount = function ($num) {
    $num = (int)$num;
    if ($num < 1000) {
        return (string)$num;
    }
    foreach ([['T', 1e12], ['B', 1e9], ['M', 1e6], ['K', 1e3]] as [$suffix, $scale]) {
        if ($num >= $scale) {
            $v = floor($num / $scale * 10) / 10; // one decimal, truncated
            $s = rtrim(rtrim(number_format($v, 1, ',', ''), '0'), ',');
            return $s . $suffix;
        }
    }
    return (string)$num;
};

$countDisplay = null;
if (isset($headerCountText)) {
    $countDisplay = $headerCountText;
} elseif (isset($headerCountApprox)) {
    $n = $headerCount ?? $paginatorCount;
    if ($n !== null && $n < PHP_INT_MAX) {
        $countDisplay = ($headerCountApprox ? '+' : '') . $abbreviateCount($n);
    }
} elseif ($totalCount !== null && $totalCount < PHP_INT_MAX) {
    $countDisplay = number_format($totalCount, 0, ',', ' ');
}

/*
 * ==============================================================
 * Header action strip
 * ==============================================================
 *
 * Each entry of `$headerActions`:
 *   'type'       navigate (plain link) | action (POST, optional confirm)
 *                | modal (openModal) | dropdown (explicitly grouped)
 *   'label'      button text
 *   'icon'       Font Awesome name, without the `fa-` prefix
 *   'url'        link target / POST target / modal source
 *   'onClick'    name of a JS function; takes over from the type's own
 *                click behaviour, the type then only decides the styling
 *   'confirm'    confirmation message (type action)
 *   'size'       modal size (type modal)
 *   'class'      whole button class, replaces the type default
 *   'id'         id of the rendered control
 *   'title'      native tooltip
 *   'tab'        only shown while that view_layout tab is active
 *   'primary'    this one keeps a button when its type is grouped
 *   'standalone' never folded into its type's group
 *   'children'   type dropdown only, same shape + ['type' => 'divider']
 *
 * Several actions sharing a behaviour (and a tab) collapse into a single
 * split button carrying that behaviour's style, so the strip never grows
 * past one control per behaviour. The last declared action of the group —
 * the rightmost button before collapsing, in practice the page's primary
 * call to action — stays the button; the others move under the attached
 * caret. Flag another one 'primary' to pick it instead.
 *
 * A page can override the grouping per behaviour:
 *
 *   $this->set('headerActionGroups', [
 *       'modal' => ['mode' => 'dropdown', 'label' => __('Create')],
 *   ]);
 *
 * mode: split (default) | dropdown (one labelled menu holding every
 * action) | none (no grouping, one button each as before).
 */
$headerActionTypes = [
    'navigate' => [
        'class' => 'btn btn-outline-dark',
        'label' => __('Navigate'),
        'icon' => 'compass',
    ],
    'action' => [
        'class' => 'btn btn-outline-primary',
        'label' => __('Operations'),
        'icon' => 'gears',
    ],
    'modal' => [
        'class' => 'btn btn-primary',
        'label' => __('Actions'),
        'icon' => 'bolt',
    ],
];

$headerActionAttributes = function (array $attributes) {
    $out = '';
    foreach ($attributes as $name => $value) {
        if ($value === null || $value === false || $value === '') {
            continue;
        }
        $out .= ' ' . $name . '="' . h($value) . '"';
    }
    return $out;
};


$headerActionItemClass = function ($class) {
    $kept = array_filter(
        preg_split('/\s+/', trim((string)$class)),
        function ($token) {
            return $token !== '' && $token !== 'btn'
                && strpos($token, 'btn-') !== 0;
        }
    );
    return trim('dropdown-item ' . implode(' ', $kept));
};

$headerActionOnClick = function (array $action) {
    if (!empty($action['onClick'])) {
        return 'event.preventDefault(); ' . $action['onClick'] . '();';
    }
    if (($action['type'] ?? '') === 'modal' && !empty($action['url'])) {
        return 'event.preventDefault(); openModal(\'' . $action['url'] . '\''
            . (empty($action['size'])
                ? ''
                : ', \'' . $action['size'] . '\'')
            . ');';
    }
    return null;
};

/**
 * Renders one action, as a standalone button or as a dropdown entry.
 * $options: asItem, class (style override), extraClass, skipTab.
 */
$renderHeaderAction = function (array $action, array $options = []) use (
    $headerActionTypes,
    $headerActionAttributes,
    $headerActionItemClass,
    $headerActionOnClick
) {
    $type = $action['type'] ?? 'navigate';
    if (!empty($options['asItem'])) {
        $class = $headerActionItemClass($action['class'] ?? '');
    } else {
        $class = ($options['class'] ?? $action['class']
                ?? $headerActionTypes[$type]['class'] ?? 'btn btn-outline-dark')
            . ' fw-semibold d-flex align-items-center gap-2';
    }
    if (!empty($options['extraClass'])) {
        $class .= ' ' . $options['extraClass'];
    }
    $tab = (!empty($action['tab']) && empty($options['skipTab']))
        ? $action['tab']
        : null;
    if ($tab !== null) {
        $class .= ' d-none';
    }
    $icon = empty($action['icon'])
        ? ''
        : '<i class="fas fa-' . h($action['icon'])
            . (empty($options['asItem']) ? '' : ' me-2') . '"></i>';
    $label = h($action['label'] ?? '');

    if ($type === 'action' && empty($action['onClick'])) {
        $linkOptions = [
            'class' => $class,
            'escape' => false,
            'inline' => false,
            'block' => 'headerActionForms',
        ];
        foreach (['id', 'title'] as $attribute) {
            if (!empty($action[$attribute])) {
                $linkOptions[$attribute] = $action[$attribute];
            }
        }
        if ($tab !== null) {
            $linkOptions['data-header-tab'] = $tab;
        }
        return $this->Form->postLink(
            $icon . $label,
            $action['url'],
            $linkOptions,
            $action['confirm'] ?? false
        );
    }

    return '<a' . $headerActionAttributes([
        'href' => $action['url'] ?? '#',
        'class' => $class,
        'id' => $action['id'] ?? null,
        'title' => $action['title'] ?? null,
        'data-header-tab' => $tab,
        'onclick' => $headerActionOnClick($action + ['type' => $type]),
    ]) . '>' . $icon . $label . '</a>';
};

$renderHeaderMenu = function (array $entries) use ($renderHeaderAction) {
    $out = '<ul class="dropdown-menu dropdown-menu-end shadow-sm">';
    foreach ($entries as $entry) {
        if (($entry['type'] ?? '') === 'divider') {
            $out .= '<li><hr class="dropdown-divider"></li>';
            continue;
        }
        $out .= '<li>' . $renderHeaderAction(
            $entry,
            ['asItem' => true, 'skipTab' => true]
        ) . '</li>';
    }
    return $out . '</ul>';
};

// Group same-behaviour actions, then normalise every slot of the strip to
// one of: button | split (button + caret) | menu (labelled dropdown).
$headerActionStrip = [];
if (!empty($headerActions)) {
    // The postLink forms of a previous render must not pile up here.
    $this->assign('headerActionForms', '');
    $groupOverrides = (isset($headerActionGroups)
        && is_array($headerActionGroups)) ? $headerActionGroups : [];
    $slots = [];
    $slotIndexes = [];
    foreach ($headerActions as $action) {
        $type = $action['type'] ?? 'navigate';
        $mode = $groupOverrides[$type]['mode'] ?? 'split';
        if (!isset($headerActionTypes[$type]) || $mode === 'none'
            || !empty($action['standalone'])
        ) {
            $slots[] = ['kind' => 'single', 'action' => $action];
            continue;
        }
        // Tab-scoped actions only ever share the strip with their own tab.
        $key = $type . '|' . ($action['tab'] ?? '');
        if (!isset($slotIndexes[$key])) {
            $slotIndexes[$key] = count($slots);
            $slots[] = [
                'kind' => 'group',
                'type' => $type,
                'mode' => $mode,
                'tab' => $action['tab'] ?? null,
                'members' => [],
            ];
        }
        $slots[$slotIndexes[$key]]['members'][] = $action;
    }

    foreach ($slots as $slot) {
        if ($slot['kind'] === 'single') {
            $action = $slot['action'];
            if (($action['type'] ?? '') !== 'dropdown') {
                $headerActionStrip[] = [
                    'kind' => 'button',
                    'action' => $action,
                ];
                continue;
            }
            $headerActionStrip[] = [
                'kind' => 'menu',
                'label' => $action['label'] ?? '',
                'icon' => $action['icon'] ?? null,
                'class' => $action['class'] ?? 'btn btn-outline-dark',
                'tab' => $action['tab'] ?? null,
                'entries' => $action['children'] ?? [],
            ];
            continue;
        }

        $members = $slot['members'];
        if (count($members) === 1) {
            $headerActionStrip[] = [
                'kind' => 'button',
                'action' => $members[0],
            ];
            continue;
        }

        $type = $slot['type'];
        $override = $groupOverrides[$type] ?? [];
        $style = $override['class'] ?? $headerActionTypes[$type]['class'];
        if ($slot['mode'] === 'dropdown') {
            $headerActionStrip[] = [
                'kind' => 'menu',
                'label' => $override['label']
                    ?? $headerActionTypes[$type]['label'],
                'icon' => array_key_exists('icon', $override)
                    ? $override['icon']
                    : $headerActionTypes[$type]['icon'],
                'class' => $style,
                'tab' => $slot['tab'],
                'entries' => $members,
            ];
            continue;
        }

        $primary = count($members) - 1;
        foreach ($members as $index => $member) {
            if (!empty($member['primary'])) {
                $primary = $index;
                break;
            }
        }
        $entries = $members;
        unset($entries[$primary]);
        $headerActionStrip[] = [
            'kind' => 'split',
            'action' => $members[$primary],
            // The visible button keeps its own style override, if any.
            'class' => $members[$primary]['class'] ?? $style,
            'tab' => $slot['tab'],
            'entries' => $entries,
        ];
    }
}
?>

<div class="container-fluid py-3">

    <div class="d-flex justify-content-between align-items-center">

        <div class="d-flex flex-column align-items-start">
            <?php if ($breadcrumb): ?>
                <span class="text-muted text-uppercase fw-semibold mb-1"
                        style="font-size:0.68rem; letter-spacing:0.07em;">
                    <?= $breadcrumb ?>
                </span>
            <?php endif; ?>
            <div class="d-flex align-items-center gap-2 ">
                <h1 class="mb-0 fw-bold lh-1 d-flex" style="font-size:2rem; word-break:break-word; max-width:100%;">
                    <?= $title ?>
                </h1>
                <?php // headerCountText => '' is the opt-out for pages whose paginator counts something other than the page's subject ?>
                <?php if ($countDisplay !== null && $countDisplay !== ''): ?>
                    <span class="badge rounded-pill bg-primary fw-semibold px-3">
                        <?= h($countDisplay) ?>
                    </span>
                <?php endif; ?>
            </div>

            <?php if (!empty($headerDescription)): ?>
                <p class="text-muted mt-1" style="font-size:0.85rem;">
                    <?= $headerDescription ?>
                </p>
            <?php else: //small space, just to match the size of the Flash messages ?>
                <div style="height: 0.5rem;"></div>
            <?php endif; ?>
        </div>

        <?php if (!empty($headerActionStrip)): ?>
            <div class="d-flex gap-2 align-items-center flex-wrap">
                <?php foreach ($headerActionStrip as $slot): ?>
                    <?php
                    $tabAttr = empty($slot['tab'])
                        ? ''
                        : ' data-header-tab="' . h($slot['tab']) . '"';
                    $tabHidden = empty($slot['tab']) ? '' : ' d-none';
                    ?>

                    <?php if ($slot['kind'] === 'button'): ?>
                        <?= $renderHeaderAction($slot['action']) ?>

                    <?php elseif ($slot['kind'] === 'split'): ?>

                        <div class="btn-group<?= $tabHidden ?>"<?= $tabAttr ?>>
                            <?= $renderHeaderAction($slot['action'], [
                                'class' => $slot['class'],
                                'skipTab' => true,
                            ]) ?>
                            <button type="button"
                                    class="<?= h($slot['class']) ?> dropdown-toggle dropdown-toggle-split"
                                    data-bs-toggle="dropdown" aria-expanded="false"
                                    aria-label="<?= h(__('More actions')) ?>"></button>
                            <?= $renderHeaderMenu($slot['entries']) ?>
                        </div>

                    <?php else: ?>

                        <div class="dropdown<?= $tabHidden ?>"<?= $tabAttr ?>>
                            <button class="<?= h($slot['class']) ?> fw-semibold d-flex align-items-center gap-2 dropdown-toggle"
                                    type="button" data-bs-toggle="dropdown" aria-expanded="false">
                                <?php if (!empty($slot['icon'])): ?>
                                    <i class="fas fa-<?= h($slot['icon']) ?>"></i>
                                <?php endif; ?>
                                <?= h($slot['label']) ?>
                            </button>
                            <?= $renderHeaderMenu($slot['entries']) ?>
                        </div>

                    <?php endif; ?>

                <?php endforeach; ?>
            </div>
            <?php // hidden CSRF forms of the POST actions, parked out of the button groups ?>
            <?= $this->fetch('headerActionForms') ?>
        <?php endif; ?>

    </div>

    <?php if (!empty($headerStats)): ?>
        <div class="row g-3 mt-2">
            <?php foreach ($headerStats as $stat): ?>
                <?php
                    $color = h($stat['color'] ?? 'secondary');
                    $subtitleColor = h($stat['subtitleColor'] ?? 'muted');
                ?>
                <div class="col-12 col-sm-6 col-xl-3">
                    <div class="card h-100 border-0 border-start border-4
                                border-<?= $color ?>"
                            style="background:var(--bs-body-secondary-bg,
                                var(--bs-secondary-bg));">
                        <div class="card-body p-3 d-flex
                                    justify-content-between align-items-start">
                            <div>
                                <div class="text-uppercase fw-semibold text-secondary mb-1"
                                        style="font-size:0.65rem; letter-spacing:0.08em;">
                                    <?= h($stat['label']) ?>
                                </div>
                                <div class="fw-bold lh-1 mb-1"
                                        style="font-size:1.75rem;">
                                    <?= h($stat['value']) ?>
                                </div>
                                <?php if (!empty($stat['subtitle'])): ?>
                                    <div class="text-<?= $subtitleColor ?>"
                                            style="font-size:0.75rem;">
                                        <?php if (!empty($stat['subtitleIcon'])): ?>
                                            <i class="fas fa-<?= h($stat['subtitleIcon']) ?> me-1"></i>
                                        <?php endif; ?>
                                        <?= h($stat['subtitle']) ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <?php if (!empty($stat['icon'])): ?>
                                <i class="fas fa-<?= h($stat['icon']) ?> text-<?= $color ?> opacity-25" style="font-size:1.25rem;"></i>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

</div>

