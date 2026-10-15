<?php
/**
 * The list of types an empty value can be enriched as: what MISP read,
 * the types the value fits, the free-text types, and a counted fold of
 * the ones it fails validation for. One search field matches type names
 * and module names, which is how a reader reaches any module.
 *
 * The same markup opens as the type chip's menu and, when nothing was
 * read, sits in the tab in place of the empty state. Picking reloads the
 * tab with `?as=`; nothing is sent to any module.
 *
 * @var array $typeView Built by value_enrichment.ctp
 * @var bool $inline In the page rather than under the chip
 */
$inline = !empty($inline);
$uid = $typeView['uid'] . ($inline ? 'i' : '');
$read = $typeView['read'];
$lead = $typeView['lead'];
$picked = $typeView['source'] === 'picked';
$choices = $typeView['choices'];
$counts = array(
    'fits' => count($choices['fits']),
    'any_text' => count($choices['any_text']),
    'fails' => count($choices['fails']),
);
$onlyFails = $counts['fits'] === 0 && $counts['any_text'] === 0;

$count = function ($n) {
    $word = __n('module', 'modules', $n);
    return '<span class="vp-et-opt-n" title="'
        . h(sprintf(__n('%d module', '%d modules', $n), $n)) . '">'
        . h($n) . '<span class="vp-et-n-word"> ' . h($word) . '</span></span>';
};

$row = 0;
$option = function ($type, $group) use (
    $typeView, $read, $lead, $picked, $uid, $count, &$row
) {
    $modules = $typeView['modulesOf'][$type];
    $current = $picked && in_array($type, $lead, true);
    $fail = $group === 'fails';
    $tags = '';
    if (in_array($type, $read, true)) {
        $tags .= '<span class="vp-et-tag">' . h(__('read')) . '</span>';
    }
    if ($current) {
        $tags .= '<span class="vp-et-tag vp-et-tag-pick">'
            . h(__('your pick')) . '</span>';
    }
    if (in_array($type, $typeView['kept'], true)) {
        $tags .= '<span class="vp-et-tag">'
            . '<i class="fas fa-clock-rotate-left" aria-hidden="true"></i>'
            . h(__('asked before')) . '</span>';
    }
    $title = $fail ? ' title="' . h(sprintf(
        __('MISP would refuse this value as %s. You can still pick it.'),
        $type
    )) . '"' : '';
    return '<button type="button" class="vp-et-opt'
        . ($fail ? ' vp-et-opt-fail' : '') . ($current ? ' is-current' : '')
        . '" role="option" tabindex="-1" id="' . h($uid . '-o' . ($row++))
        . '" data-vp-et-type="' . h($type) . '" data-vp-et-modules="'
        . h(json_encode(array_values($modules))) . '" aria-selected="'
        . ($current ? 'true' : 'false') . '"' . $title . '>'
        . '<span class="vp-et-opt-mark" aria-hidden="true">'
        . ($current ? '<i class="fas fa-check"></i>' : '') . '</span>'
        . '<span class="vp-et-opt-main"><span class="vp-et-opt-line">'
        . '<span class="vp-et-opt-name" data-vp-et-name>' . h($type)
        . '</span>' . $tags . '</span>'
        . '<span class="vp-et-opt-hits" data-vp-et-hits hidden></span></span>'
        . $count(count($modules)) . '</button>';
};

$group = function ($name) use ($choices, $option) {
    $out = '';
    foreach ($choices[$name] as $choice) {
        $out .= $option($choice['type'], $name);
    }
    return $out;
};

$readModules = array();
foreach ($read as $type) {
    if (isset($typeView['modulesOf'][$type])) {
        $readModules = array_merge(
            $readModules,
            $typeView['modulesOf'][$type]
        );
    }
}
$readModules = array_values(array_unique($readModules));
sort($readModules);
$popClass = 'dropdown-menu vp-et-pop'
    . ($inline ? ' vp-et-pop-inline show' : '');
?>
<div class="<?= h($popClass) ?>"
     id="<?= h($uid) ?>-pop"
     data-vp-et-pop
     <?= $inline ? 'data-vp-et-inline' : 'role="dialog" aria-label="'
        . h(__('Types to match modules on')) . '"' ?>
     data-vp-et-peek-idle="<?= h(__('Picking a type only changes which'
        . ' modules are listed below. Nothing is sent until you press'
        . ' Run.')) ?>"
     data-vp-et-peek-type="<?= h(__('%s taken by')) ?>"
     data-vp-et-peek-back="<?= h(__('Back to %s, taken by')) ?>"
     data-vp-et-peek-fold="<?= h(__('Types this value fails validation'
        . ' for. Still pickable; the tab warns once you do.')) ?>"
     data-vp-et-more="<?= h(__('+%d more · type to narrow')) ?>"
     data-vp-et-more-all="<?= h(__('%d types · type to narrow')) ?>"
     data-vp-et-nothing="<?= h(__('Nothing matches “%s” — no type, and'
        . ' no enabled module by that name.')) ?>">

    <div class="vp-et-search">
        <i class="fas fa-magnifying-glass" aria-hidden="true"></i>
        <input type="text" class="vp-et-input" role="combobox"
               aria-autocomplete="list" aria-expanded="true"
               aria-controls="<?= h($uid) ?>-list"
               aria-label="<?= h(__('Search types and module names')) ?>"
               placeholder="<?= h(__('Search a type or a module…')) ?>"
               autocomplete="off" spellcheck="false">
    </div>

    <div class="vp-et-list" role="listbox" id="<?= h($uid) ?>-list"
         aria-label="<?= h(__('Types to match modules on')) ?>">

        <?php if (!empty($read)): ?>
            <?php $isRead = $typeView['source'] === 'read'; ?>
            <div class="vp-et-sec vp-et-sec-read">
                <div class="vp-et-sec-h">
                    <span><?= h(__('Read from the value')) ?></span>
                </div>
                <div class="vp-et-grid">
                    <button type="button"
                            class="vp-et-opt vp-et-opt-reset<?= $isRead
                                ? ' is-current' : '' ?>"
                            role="option" tabindex="-1"
                            id="<?= h($uid) ?>-read"
                            data-vp-et-reset
                            data-vp-et-modules="<?= h(json_encode(
                                $readModules
                            )) ?>"
                            aria-selected="<?= $isRead ? 'true' : 'false' ?>">
                        <span class="vp-et-opt-mark" aria-hidden="true">
                            <i class="fas <?= $isRead
                                ? 'fa-check' : 'fa-rotate-left' ?>"></i>
                        </span>
                        <span class="vp-et-opt-main">
                            <span class="vp-et-opt-line">
                                <span class="vp-et-opt-name"><?=
                                    h(implode(', ', $read)) ?></span>
                            </span>
                        </span>
                        <?= $count(count($readModules)) ?>
                    </button>
                </div>
                <div class="vp-et-more" data-vp-et-more hidden></div>
            </div>
        <?php endif; ?>

        <div class="vp-et-sec vp-et-sec-fits"<?= $counts['fits']
            ? '' : ' hidden' ?>>
            <div class="vp-et-sec-h">
                <span><?= h(__('Fits the value')) ?></span>
                <span class="vp-et-sec-n" data-vp-et-n><?=
                    h($counts['fits']) ?></span>
            </div>
            <div class="vp-et-grid"><?= $group('fits') ?></div>
            <div class="vp-et-more" data-vp-et-more hidden></div>
        </div>

        <div class="vp-et-sec vp-et-sec-any"<?= $counts['any_text']
            ? '' : ' hidden' ?>>
            <div class="vp-et-sec-h">
                <span><?= h(__('Accepts any text')) ?></span>
                <span class="vp-et-sec-n" data-vp-et-n><?=
                    h($counts['any_text']) ?></span>
                <span class="vp-et-sec-hint"><?=
                    h(__('takes any string')) ?></span>
            </div>
            <div class="vp-et-grid"><?= $group('any_text') ?></div>
            <div class="vp-et-more" data-vp-et-more hidden></div>
        </div>

        <?php if ($counts['fails'] > 0): ?>
            <div class="vp-et-sec vp-et-sec-fails<?= $onlyFails
                ? ' is-only' : '' ?>">
                <button type="button" class="vp-et-fold" tabindex="-1"
                        id="<?= h($uid) ?>-fold" aria-expanded="false"
                        data-vp-et-fold>
                    <i class="fas fa-chevron-right vp-et-fold-chev"
                       aria-hidden="true"></i>
                    <span class="vp-et-fold-label"><?=
                        h(__('Fails validation')) ?></span>
                    <span class="vp-et-fold-n" data-vp-et-n><?=
                        h($counts['fails']) ?></span>
                    <span class="vp-et-fold-hint"><?= h($onlyFails
                        ? __('MISP would refuse the value as any of these'
                            . ' — each can still be picked')
                        : __('MISP would refuse the value as these')) ?></span>
                </button>
                <div class="vp-et-grid" data-vp-et-failgrid hidden><?=
                    $group('fails') ?></div>
                <div class="vp-et-more" data-vp-et-more hidden></div>
            </div>
        <?php endif; ?>

        <div class="vp-et-nothing" data-vp-et-nothing hidden></div>
    </div>

    <div class="dropdown-divider vp-et-divider" aria-hidden="true"></div>
    <div class="vp-et-foot">
        <div class="vp-et-peek" data-vp-et-peek><?= h(__('Picking a type only'
            . ' changes which modules are listed below. Nothing is sent'
            . ' until you press Run.')) ?></div>
        <?php if ($typeView['workflow']): ?>
            <div class="vp-et-foot-note vp-et-foot-wf">
                <i class="fas fa-ban" aria-hidden="true"></i>
                <span><?= h(__('Runs are refused on this instance, whichever'
                    . ' type you pick.')) ?></span>
            </div>
        <?php endif; ?>
        <?php if (!$typeView['canRun']): ?>
            <div class="vp-et-foot-note">
                <i class="fas fa-lock" aria-hidden="true"></i>
                <span><?= h(__('You can look through every type. Running a'
                    . ' module needs the add permission.')) ?></span>
            </div>
        <?php endif; ?>
    </div>
</div>
