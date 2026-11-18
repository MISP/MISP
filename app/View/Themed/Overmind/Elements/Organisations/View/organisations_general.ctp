<?php
/*
 * The organisation's identity card: an aside holding its logo, or its
 * monogram as the indexes draw it, with the reader's grade in the corner,
 * tinted by whether the organisation is local or remote, beside what
 * describes it. Its id, UUID and dates are in the page header.
 */
App::uses('OrgGradeTool', 'Tools/AnalystProfile');

$org = $data['Organisation'] ?? [];
$local = !empty($org['local']);

$grading = $this->OrgGrade->reading();
$gradable = $this->OrgGrade->enabled($grading) && !empty($org['uuid']);

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$tone = $local ? 'success' : 'secondary';

$scopePill = $local
    ? '<span class="badge rounded-pill text-bg-success d-inline-flex align-items-center gap-1">'
        . '<i class="fas fa-house"></i>' . __('Local') . '</span>'
    : '<span class="badge rounded-pill text-bg-light border d-inline-flex align-items-center gap-1 fw-normal text-muted">'
        . '<i class="fas fa-globe"></i>' . __('Remote') . '</span>';

$domains = $org['restricted_to_domain'] ?? [];
if (!is_array($domains)) {
    $decoded = json_decode((string)$domains, true);
    $domains = is_array($decoded) ? $decoded : preg_split('/[\r\n,]+/', trim((string)$domains), -1, PREG_SPLIT_NO_EMPTY);
}
$domains = array_values(array_filter(array_map('trim', $domains), 'strlen'));

$nationality = trim($org['nationality'] ?? '');
$countryCode = (string)($org['country_code'] ?? '');
$flag = $countryCode !== '' ? $this->Icon->countryFlag($countryCode, $nationality) : '';

$facts = [
    [
        'tile' => '<i class="fas fa-shapes"></i>',
        'value' => trim($org['type'] ?? ''),
        'label' => __('Type'),
    ],
    [
        'tile' => '<i class="fas fa-industry"></i>',
        'value' => trim($org['sector'] ?? ''),
        'label' => __('Sector'),
    ],
    [
        'tile' => $flag !== '' ? $flag : '<i class="fas fa-flag"></i>',
        'value' => $nationality,
        'label' => $countryCode !== '' ? __('Nationality') . ' · ' . strtoupper($countryCode) : __('Nationality'),
    ],
];
if ($gradable) {
    $grade = OrgGradeTool::gradeOf($grading['grades'], $org['uuid']);
    $facts[] = [
        'tile' => $this->OrgGrade->badge($org, $grading, 'square'),
        'bare' => true,
        'value_html' => sprintf(
            '<span class="og-words%s" data-grade-words-for="%s" data-grade-empty="%s">%s</span>',
            $grade === null ? ' is-empty' : '',
            h(strtolower($org['uuid'])),
            h(__('Not graded')),
            h($grade === null ? __('Not graded') : $grading['labels'][$grade])
        ),
        'label' => __('Reliability'),
    ];
}
$description = trim($org['description'] ?? '');
$contacts = trim($org['contacts'] ?? '');
echo $gradable ? $this->OrgGrade->config($grading) : '';
?>
<div class="card shadow-sm mb-3 overflow-hidden">
    <div class="row g-0">

        <div class="col-12 col-md-4 col-xl-3 ov-identity-aside p-3 d-flex flex-column gap-3 bg-<?= $tone ?>-subtle">
            <div class="align-self-start"><?= $scopePill ?></div>
            <div class="d-flex justify-content-center align-items-center flex-grow-1 pb-2">
                <div class="org-hero" title="<?= h($org['name'] ?? '') ?>">
                    <span class="org-hero-tile border border-2 border-<?= $tone ?>"><?= $this->EventIndex->orgTile($org, 72) ?></span>
                    <?= $gradable ? $this->OrgGrade->badge($org, $grading, 'hero') : '' ?>
                </div>
            </div>
        </div>

        <div class="col">
            <div class="p-3 d-flex flex-column gap-3 h-100">

                <div>
                    <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>">
                        <i class="misp-icon misp-icon-organisation misp-simple text-primary me-1"></i><?= __('Organisation') ?>
                    </div>
                    <?php if ($description !== ''): ?>
                        <div class="border-start border-3 border-primary bg-primary-subtle bg-opacity-25 rounded-end px-3 py-2 text-break">
                            <?= nl2br(h($description), false) ?>
                        </div>
                    <?php else: ?>
                        <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
                    <?php endif; ?>
                </div>

                <div class="row row-cols-1 row-cols-sm-<?= count($facts) > 3 ? '2 row-cols-xl-4' : '3' ?> g-2">
                    <?php foreach ($facts as $fact): ?>
                        <?php $value = $fact['value'] ?? ''; ?>
                        <div class="col">
                            <div class="d-flex align-items-center gap-2 min-w-0<?= !isset($fact['value_html']) && $value === '' ? ' opacity-75' : '' ?>">
                                <?php if (!empty($fact['bare'])): ?>
                                    <span class="og-slot d-inline-flex flex-shrink-0"
                                          style="<?= $tileStyle ?>"><?= $fact['tile'] ?></span>
                                <?php else: ?>
                                    <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary text-body-secondary overflow-hidden"
                                          style="<?= $tileStyle ?>"><?= $fact['tile'] ?></span>
                                <?php endif; ?>
                                <div class="min-w-0">
                                    <?php if (isset($fact['value_html'])): ?>
                                        <div class="fw-semibold lh-sm text-truncate"><?= $fact['value_html'] ?></div>
                                    <?php else: ?>
                                        <div class="fw-semibold lh-sm text-truncate<?= $value === '' ? ' text-body-secondary fst-italic fw-normal' : '' ?>"
                                             title="<?= h($value) ?>"><?= $value !== '' ? h($value) : __('Not set') ?></div>
                                    <?php endif; ?>
                                    <div class="small text-body-secondary"><?= h($fact['label']) ?></div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <div>
                    <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Domain restrictions') ?></div>
                    <?php if (empty($domains)): ?>
                        <span class="text-body-secondary small"><?= __('None — its users can have any e-mail address.') ?></span>
                    <?php else: ?>
                        <div class="d-flex flex-wrap align-items-center gap-1">
                            <?php foreach ($domains as $domain): ?>
                                <span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal font-monospace">
                                    <i class="fas fa-at me-1 opacity-50"></i><?= h($domain) ?>
                                </span>
                            <?php endforeach; ?>
                        </div>
                        <div class="small text-body-secondary mt-1"><?= __('A new user of this organisation needs an e-mail address in one of these domains.') ?></div>
                    <?php endif; ?>
                </div>

                <?php if ($contacts !== ''): ?>
                    <div>
                        <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Contact information') ?></div>
                        <div class="small text-break bg-body-tertiary border rounded-2 px-3 py-2"><?= nl2br(h($contacts), false) ?></div>
                    </div>
                <?php endif; ?>

            </div>
        </div>

    </div>
</div>
