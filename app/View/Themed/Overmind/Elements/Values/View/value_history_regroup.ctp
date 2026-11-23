<?php
/**
 * The History tab's sections by organisation or by field. They are drawn
 * empty: value-intelligence.js moves the entries into them when the grouping
 * switches, by the body id each entry names (`data-vp-audit-org` / `-field`).
 *
 * @var string $grouping org or field
 * @var array $sections
 * @var callable $bodyId section key => body id
 * @var callable $renderMix
 * @var callable $renderCount
 * @var callable $fmt
 * @var int $pageSize
 * @var int $sectionSize
 */
?>
<div data-vp-audit-grouping="<?= h($grouping) ?>" hidden>
    <?php foreach ($sections as $index => $section): ?>
        <?php
        $id = $bodyId($grouping === 'org' ? $section['id'] : $section['key']);
        $open = $index === 0;
        if ($grouping === 'org') {
            $sub = $section['own']
                ? __('your organisation')
                : ($section['actors'] > 0
                    ? sprintf(__n('%d named user', '%d named users', $section['actors']), $section['actors'])
                    : __('its users are not named to you'));
        } else {
            $sub = strpos($section['key'], ',') !== false ? __('changed together by one edit') : '';
        }
        ?>
        <div class="vp-hx-sec" data-vp-audit-section data-vp-audit-total="<?= h($section['count']) ?>">
            <div class="vp-hx-head">
                <button type="button" class="vp-hx-toggle" data-vp-audit-toggle
                        aria-expanded="<?= $open ? 'true' : 'false' ?>" aria-controls="<?= h($id) ?>">
                    <i class="fas fa-chevron-<?= $open ? 'down' : 'right' ?>" data-vp-audit-chevron aria-hidden="true"></i>
                </button>
                <div class="vp-hx-title">
                    <?php if ($grouping === 'org'): ?>
                        <?= $this->element('Values/View/value_org_link', array(
                            'org' => array('id' => $section['id'], 'name' => $section['name']),
                        )) ?>
                    <?php else: ?>
                        <span class="vp-hx-event<?= strpos($section['key'], 'field:') === 0 ? ' font-monospace' : '' ?>"><?= h($section['label']) ?></span>
                    <?php endif; ?>
                    <?php if ($sub !== ''): ?>
                        <div class="vp-hx-sub"><?= h($sub) ?></div>
                    <?php endif; ?>
                </div>
                <div class="vp-hx-tally">
                    <?= $renderMix($section['mix'], $section['count']) ?>
                    <?= $renderCount($section['count']) ?>
                </div>
                <div class="vp-hx-last">
                    <?php if ($section['last'] !== null): ?>
                        <span title="<?= h(__('Last entry')) ?>"><?= h($fmt($section['last'], 'j M Y')) ?></span>
                    <?php endif; ?>
                </div>
            </div>
            <div id="<?= h($id) ?>" class="vp-hx-body<?= $open ? '' : ' d-none' ?>" data-vp-audit-body>
                <?php if ($section['count'] > $pageSize): ?>
                    <div class="vp-hx-pager" data-vp-audit-pagerhost>
                        <?= $this->element('Values/View/value_pager', array(
                            'size' => $pageSize,
                            'shown' => $section['count'],
                            'total' => $section['count'],
                            'noun' => array('one' => __('entry'), 'many' => __('entries')),
                        )) ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    <?php endforeach; ?>

    <?php if (count($sections) > $sectionSize): ?>
        <div class="vp-hx-pager" data-vp-audit-sectionpager>
            <?= $this->element('Values/View/value_pager', array(
                'size' => $sectionSize,
                'shown' => count($sections),
                'total' => count($sections),
                'noun' => $grouping === 'org'
                    ? array('one' => __('organisation'), 'many' => __('organisations'))
                    : array('one' => __('group'), 'many' => __('groups')),
            )) ?>
        </div>
    <?php endif; ?>
</div>
