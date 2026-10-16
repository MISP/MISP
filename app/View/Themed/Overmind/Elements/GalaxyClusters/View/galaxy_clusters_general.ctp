<?php
$galaxyName = $data['Galaxy']['name'] ?? $data['Galaxy']['type'] ?? '';
$iconClass = !empty($data['Galaxy']['icon']) ? $this->FontAwesome->getClass($data['Galaxy']['icon']) : 'fas fa-diagram-project';
$palette = $this->GalaxyColour->palette($galaxyName);

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$authors = !empty($data['authors']) ? (is_array($data['authors']) ? implode(', ', $data['authors']) : $data['authors']) : '';
$source = (string)($data['source'] ?? '');
$sourceIsUrl = $source !== '' && filter_var($source, FILTER_VALIDATE_URL) && preg_match('/^https?:\/\//i', $source);

$flags = [
    [
        'on' => !empty($data['published']),
        'colour' => 'success',
        'icon' => 'fas fa-upload',
        'label' => [__('Published'), __('Unpublished')],
        'sub' => [__('Pushed to connected instances'), __('Not pushed to connected instances yet')],
    ],
    [
        'on' => !empty($data['default']),
        'colour' => 'primary',
        'icon' => 'fas fa-box',
        'label' => [__('Default'), __('Custom')],
        'sub' => [__('Shipped with MISP, updated from the galaxy library'), __('Created on a MISP instance')],
    ],
];

$usage = [
    [
        'count' => (int)($data['tag_count'] ?? 0),
        'icon' => 'misp-icon misp-icon-event misp-simple',
        'scope' => 'event',
        'noun' => [__('event'), __('events')],
        'url' => $baseurl . '/events/index/searchtag:' . ($data['tag_id'] ?? ''),
    ],
    [
        'count' => (int)($data['tag_att_count'] ?? 0),
        'icon' => 'misp-icon misp-icon-attribute misp-simple',
        'scope' => 'attribute',
        'noun' => [__('attribute'), __('attributes')],
        'url' => $baseurl . '/attributes/index?tags=' . ($data['tag_id'] ?? ''),
    ],
];

$parent = $data['extended_from']['GalaxyCluster'] ?? null;
$children = $data['extended_by'] ?? [];
?>
<div class="card mb-3 shadow-sm" data-tour="cluster-general">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="<?= h($iconClass) ?> me-1" style="color:<?= h($palette['tintIcon']) ?>;"></i><?= __('Cluster') ?>
                </span>
                <span class="d-flex flex-wrap align-items-center gap-1">
                    <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle">
                        v<?= h((int)($data['version'] ?? 0)) ?>
                    </span>
                </span>
            </div>
            <?php if (trim($data['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 rounded-end px-3 py-2 text-break"
                     style="border-color:<?= h($palette['tintIcon']) ?> !important;background:<?= h($palette['sectionBg']) ?>;">
                    <?= nl2br(h($data['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Tagging') ?></div>
            <div class="d-flex flex-wrap align-items-center gap-2">
                <?php if (!empty($data['tag_name'])): ?>
                    <button type="button" class="ov-copy-target focus-ring d-inline-flex align-items-center gap-1 border rounded-pill bg-body-tertiary font-monospace text-body-secondary px-2 mb-0 mw-100 lh-base"
                            title="<?= h(__('Copy the tag')) ?>"
                            data-copy-value="<?= h($data['tag_name']) ?>"
                            data-copy-msg="<?= h(__('Tag copied to clipboard')) ?>"
                            onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">
                        <i class="fas fa-tag opacity-50"></i><span class="text-truncate"><?= h($data['tag_name']) ?></span><i class="fas fa-copy fa-xs"></i>
                    </button>
                <?php endif; ?>
            </div>
        </div>

        <?php if ($source !== '' || $authors !== ''): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Source & authors') ?></div>
                <div class="d-flex flex-wrap align-items-center gap-2">
                    <?php if ($source !== ''): ?>
                        <?php if ($sourceIsUrl): ?>
                            <a class="badge rounded-pill border bg-body text-body-secondary fw-normal text-decoration-none text-truncate" style="max-width:24rem;"
                               href="<?= h($source) ?>" rel="noreferrer noopener" target="_blank" title="<?= h(__('Source')) ?>: <?= h($source) ?>">
                                <i class="fas fa-arrow-up-right-from-square me-1 opacity-50"></i><?= h(parse_url($source, PHP_URL_HOST) ?: $source) ?>
                            </a>
                        <?php else: ?>
                            <span class="badge rounded-pill border bg-body text-body-secondary fw-normal" title="<?= h(__('Source')) ?>">
                                <i class="fas fa-book me-1 opacity-50"></i><?= h($source) ?>
                            </span>
                        <?php endif; ?>
                    <?php endif; ?>
                    <?php if ($authors !== ''): ?>
                        <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal text-truncate" style="max-width:24rem;"
                              title="<?= h(__('Authors')) ?>: <?= h($authors) ?>">
                            <i class="fas fa-user-pen me-1 opacity-50"></i><?= h($authors) ?>
                        </span>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Status & usage') ?></div>
            <div class="d-flex flex-wrap row-gap-2 column-gap-3">
                <?php foreach ($flags as $flag): ?>
                    <?php $state = $flag['on'] ? 0 : 1; ?>
                    <div class="d-flex align-items-center gap-2 min-w-0<?= $flag['on'] ? '' : ' opacity-75' ?>" style="flex:1 1 11rem;">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $flag['on']
                            ? 'bg-' . $flag['colour'] . '-subtle text-' . $flag['colour'] . '-emphasis'
                            : 'bg-body-secondary text-body-secondary' ?>"
                              style="<?= $tileStyle ?>">
                            <i class="<?= h($flag['icon']) ?>"></i>
                        </span>
                        <div class="min-w-0">
                            <div class="fw-semibold lh-sm<?= $flag['on'] ? '' : ' text-body-secondary' ?>"><?= h($flag['label'][$state]) ?></div>
                            <div class="small text-body-secondary text-truncate" title="<?= h($flag['sub'][$state]) ?>"><?= h($flag['sub'][$state]) ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
                <?php foreach ($usage as $use): ?>
                    <?php $linked = $use['count'] > 0 && !empty($data['tag_id']); ?>
                    <<?= $linked ? 'a href="' . h($use['url']) . '"' : 'div' ?>
                        class="d-flex align-items-center gap-2 min-w-0 text-decoration-none link-body-emphasis<?= $use['count'] > 0 ? '' : ' opacity-75' ?>"
                        style="flex:1 1 11rem;"<?= $linked ? ' title="' . h(__('Show them')) . '"' : '' ?>>
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3<?= $use['count'] > 0 ? '' : ' bg-body-secondary text-body-secondary' ?>"
                              style="<?= $tileStyle ?><?= $use['count'] > 0
                                  ? 'background:rgba(var(--bs-' . $use['scope'] . '-rgb),.12);color:rgb(var(--bs-' . $use['scope'] . '-rgb));'
                                  : '' ?>">
                            <i class="<?= h($use['icon']) ?>"></i>
                        </span>
                        <div class="min-w-0">
                            <div class="fw-semibold lh-sm"><?= h(number_format($use['count'], 0, ',', ' ')) ?> <?= h($use['noun'][$use['count'] === 1 ? 0 : 1]) ?></div>
                            <div class="small text-body-secondary text-truncate"><?= __('Tagged with this cluster') ?></div>
                        </div>
                    </<?= $linked ? 'a' : 'div' ?>>
                <?php endforeach; ?>
            </div>
        </div>

        <?php if (!empty($parent) || !empty($children)): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Lineage') ?></div>
                <?php if (!empty($parent)): ?>
                    <a href="<?= h($baseurl . '/galaxy_clusters/view/' . $parent['id']) ?>"
                       class="d-flex align-items-center gap-3 p-2 rounded-3 border bg-body-tertiary text-decoration-none link-body-emphasis ov-mini-card">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3"
                              style="width:2.25rem;height:2.25rem;background:<?= h($palette['tintBg']) ?>;color:<?= h($palette['tintIcon']) ?>;">
                            <i class="fas fa-code-branch"></i>
                        </span>
                        <div class="min-w-0 flex-grow-1">
                            <div class="small text-body-secondary"><?= __('Forked from') ?></div>
                            <div class="fw-semibold lh-sm text-truncate"><?= h($parent['value']) ?></div>
                        </div>
                        <span class="badge rounded-pill border bg-body text-body-secondary fw-normal flex-shrink-0"
                              title="<?= h(__('Version this fork was taken from')) ?>">
                            v<?= h($data['extends_version'] ?? '') ?>
                        </span>
                        <i class="fas fa-arrow-right flex-shrink-0 text-body-secondary"></i>
                    </a>
                    <?php if (!empty($newVersionAvailable)): ?>
                        <div class="d-flex align-items-center gap-2 p-2 mt-2 rounded-2 bg-warning-subtle text-warning-emphasis border-start border-3 border-warning small">
                            <i class="fas fa-triangle-exclamation"></i>
                            <span class="me-auto"><?= __('Version %s of the original is available.', h($parent['version'])) ?></span>
                            <?= $this->Form->postLink(
                                __('Update this cluster'),
                                $baseurl . '/galaxy_clusters/updateCluster/' . h($data['id']),
                                ['class' => 'btn btn-sm btn-warning']
                            ) ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
                <?php if (!empty($children)): ?>
                    <div class="d-flex flex-wrap align-items-center gap-1 mt-2">
                        <span class="small text-body-secondary me-1"><?= __('Forked by') ?></span>
                        <?= $this->TagChip->clusters($children) ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

    </div>
</div>
