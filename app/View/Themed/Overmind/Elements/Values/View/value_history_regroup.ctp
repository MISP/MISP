<?php
/**
 * One alternative grouping of the History tab's rows: the section
 * headers and empty bodies the script moves rows into when the reader
 * picks it. Hidden until then.
 *
 * @var string $grouping `org` or `field`
 * @var array $sections From `ValueIntelligence::historyRegroups()`
 * @var callable $bodyId Section key => body element id
 * @var callable $renderMix
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
                    ? sprintf(
                        __n('%d named user', '%d named users',
                            $section['actors']),
                        $section['actors']
                    )
                    : __('its users are not named to you'));
        } else {
            $sub = strpos($section['key'], ',') !== false
                ? __('changed together by one edit')
                : '';
        }
        $plain = sprintf(
            __n('%d entry', '%d entries', $section['count']),
            $section['count']
        );
        ?>
        <div class="border-bottom"
             data-vp-audit-section
             data-vp-audit-total="<?= h($section['count']) ?>">
            <div class="d-flex align-items-center gap-2 gap-lg-3 p-2 px-3
                        flex-wrap">
                <button type="button"
                        class="btn btn-sm btn-link text-decoration-none p-0
                               text-body d-flex align-items-center gap-2
                               vp-min-w-0"
                        data-vp-audit-toggle
                        aria-expanded="<?= $open ? 'true' : 'false' ?>"
                        aria-controls="<?= h($id) ?>">
                    <i class="fas fa-chevron-<?= $open ? 'down' : 'right' ?>"
                       data-vp-audit-chevron></i>
                    <span class="small fw-semibold text-truncate<?=
                        $grouping === 'field'
                            && strpos($section['key'], 'field:') === 0
                            ? ' font-monospace' : '' ?>"><?=
                        h($grouping === 'org'
                            ? $section['name']
                            : $section['label']) ?></span>
                </button>
                <div class="vp-min-w-0 flex-grow-1 text-muted"
                     style="font-size: 0.7rem;"><?= h($sub) ?></div>
                <div class="flex-shrink-0" style="width: 8.5rem;">
                    <?= $renderMix($section['mix'], $section['count']) ?>
                    <div class="text-muted" style="font-size: 0.7rem;"
                         data-vp-audit-count
                         data-vp-audit-plain="<?= h($plain) ?>"
                         data-vp-audit-tpl="<?= h(__n(
                             '%1$s of %2$s entry',
                             '%1$s of %2$s entries',
                             $section['count']
                         )) ?>"><?= h($plain) ?></div>
                </div>
                <div class="text-muted text-end flex-shrink-0"
                     style="width: 6rem; font-size: 0.7rem;">
                    <?= h($section['last'] === null
                        ? '' : $fmt($section['last'], 'j M Y')) ?>
                </div>
            </div>
            <div id="<?= h($id) ?>" data-vp-audit-body
                 class="<?= $open ? '' : 'd-none' ?>">
                <?php if ($section['count'] > $pageSize): ?>
                    <div class="px-3 py-2 border-top"
                         data-vp-audit-pagerhost>
                        <?= $this->element('Values/View/value_pager', array(
                            'size' => $pageSize,
                            'shown' => $section['count'],
                            'total' => $section['count'],
                            'noun' => array(
                                'one' => __('entry'),
                                'many' => __('entries'),
                            ),
                        )) ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    <?php endforeach; ?>

    <?php if (count($sections) > $sectionSize): ?>
        <div class="px-3 py-2 border-top" data-vp-audit-sectionpager>
            <?= $this->element('Values/View/value_pager', array(
                'size' => $sectionSize,
                'shown' => count($sections),
                'total' => count($sections),
                'noun' => $grouping === 'org'
                    ? array(
                        'one' => __('organisation'),
                        'many' => __('organisations'),
                    )
                    : array(
                        'one' => __('group'),
                        'many' => __('groups'),
                    ),
            )) ?>
        </div>
    <?php endif; ?>
</div>
