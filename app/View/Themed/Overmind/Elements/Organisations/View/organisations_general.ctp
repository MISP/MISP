<?php
/*
 * The organisation's identity card: an aside holding the logo (or a glyph when
 * there is none), tinted by whether the organisation is local or remote, beside
 * what describes it. Its id, UUID and dates are in the page header.
 */
$org = $data['Organisation'] ?? [];
$local = !empty($org['local']);

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$tone = $local ? 'success' : 'secondary';
$logo = $this->OrgImg->getOrgLogoV2($org, 72, false);

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
$description = trim($org['description'] ?? '');
$contacts = trim($org['contacts'] ?? '');
?>
<div class="card shadow-sm mb-3 overflow-hidden">
    <div class="row g-0">

        <div class="col-12 col-md-4 col-xl-3 ov-identity-aside p-3 d-flex flex-column gap-3 bg-<?= $tone ?>-subtle">
            <div class="align-self-start"><?= $scopePill ?></div>
            <div class="d-flex justify-content-center align-items-center flex-grow-1 pb-2">
                <div class="rounded-circle d-flex align-items-center justify-content-center overflow-hidden bg-body border border-2 border-<?= $tone ?> text-<?= $tone ?>"
                     style="width:110px; height:110px;"
                     title="<?= h($org['name'] ?? '') ?>">
                    <?php if ($logo !== ''): ?>
                        <?= $logo ?>
                    <?php else: ?>
                        <i class="fas fa-building fa-3x"></i>
                    <?php endif; ?>
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

                <div class="row row-cols-1 row-cols-sm-3 g-2">
                    <?php foreach ($facts as $fact): ?>
                        <div class="col">
                            <div class="d-flex align-items-center gap-2 min-w-0<?= $fact['value'] === '' ? ' opacity-75' : '' ?>">
                                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary text-body-secondary overflow-hidden"
                                      style="<?= $tileStyle ?>"><?= $fact['tile'] ?></span>
                                <div class="min-w-0">
                                    <div class="fw-semibold lh-sm text-truncate<?= $fact['value'] === '' ? ' text-body-secondary fst-italic fw-normal' : '' ?>"
                                         title="<?= h($fact['value']) ?>"><?= $fact['value'] !== '' ? h($fact['value']) : __('Not set') ?></div>
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
