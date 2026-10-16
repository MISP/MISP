<?php
/*
 * A community from the MISP project's community list (files/community-metadata).
 * Its logo is a remote URL and is deliberately not loaded: viewing the page
 * should not tell a third party that this instance looked at it.
 */
// The community list fills unknown fields with the string "undefined".
foreach ($data as $field => $value) {
    if (is_string($value) && strtolower(trim($value)) === 'undefined') {
        $data[$field] = '';
    }
}

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$vetted = !empty($data['misp_project_vetted']);
$selfRegistration = array_key_exists('self_registration', $data) ? !empty($data['self_registration']) : null;
$localOrg = $hostOrg['Organisation'] ?? null;
$hostName = $localOrg['name'] ?? ($data['org_name'] ?? ($data['Org']['name'] ?? ''));
$email = trim((string)($data['email'] ?? ''));
$pgpKey = trim((string)($data['pgp_key'] ?? ''));

$url = (string)($data['url'] ?? '');
$isLink = (bool)preg_match('/^https?:\/\//i', $url);

$facts = [
    [
        'icon' => 'fas fa-shapes',
        'label' => (string)($data['type'] ?? ''),
        'sub' => __('Type'),
    ],
    [
        'icon' => 'fas fa-industry',
        'label' => (string)($data['sector'] ?? ''),
        'sub' => __('Sector'),
    ],
    [
        'icon' => 'fas fa-flag',
        'label' => (string)($data['nationality'] ?? ''),
        'sub' => __('Nationality'),
    ],
];

$tile = function ($tileHtml, $titleHtml, $sub, $muted = false) use ($tileStyle) {
    return '<div class="d-flex align-items-center gap-2 min-w-0' . ($muted ? ' opacity-75' : '') . '">'
        . str_replace('{STYLE}', $tileStyle, $tileHtml)
        . '<div class="min-w-0">' . $titleHtml
        . '<div class="small text-body-secondary text-truncate">' . h($sub) . '</div></div></div>';
};
$plainTile = '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary text-body-secondary" style="{STYLE}"><i class="%s"></i></span>';

$hostTile = $tile(
    '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary overflow-hidden" style="{STYLE}">'
        . (($localOrg ? $this->OrgImg->getOrgLogoV2($localOrg, 20, false) : '') ?: '<i class="fas fa-building text-body-secondary"></i>')
        . '</span>',
    $localOrg
        ? '<a class="d-block fw-semibold lh-sm text-truncate text-decoration-none" href="' . h($baseurl . '/organisations/view/' . $localOrg['id']) . '">' . h($hostName) . '</a>'
        : '<div class="fw-semibold lh-sm text-truncate">' . h($hostName) . '</div>',
    __('Hosts the community')
);

$joiningTiles = [];
if ($selfRegistration !== null) {
    $joiningTiles[] = $tile(
        '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 '
            . ($selfRegistration ? 'bg-success-subtle text-success-emphasis' : 'bg-body-secondary text-body-secondary')
            . '" style="{STYLE}"><i class="fas fa-user-plus"></i></span>',
        '<div class="fw-semibold lh-sm' . ($selfRegistration ? '' : ' text-body-secondary') . '">'
            . h($selfRegistration ? __('Self-registration') : __('On request')) . '</div>',
        $selfRegistration ? __('Organisations can sign up themselves') : __('Membership goes through its administrators'),
        !$selfRegistration
    );
}
if ($email !== '') {
    $joiningTiles[] = $tile(
        sprintf($plainTile, 'fas fa-envelope'),
        '<a class="d-block fw-semibold lh-sm text-truncate text-decoration-none" href="mailto:' . h($email) . '">' . h($email) . '</a>',
        __('Contact')
    );
}

$factTiles = [];
foreach ($facts as $fact) {
    if ($fact['label'] === '') {
        continue;
    }
    $factTiles[] = $tile(
        sprintf($plainTile, h($fact['icon'])),
        '<div class="fw-semibold lh-sm text-truncate" title="' . h($fact['label']) . '">' . h($fact['label']) . '</div>',
        $fact['sub']
    );
}
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="fas fa-people-group text-primary me-1"></i><?= __('Community') ?>
                </span>
                <span class="d-flex flex-wrap align-items-center gap-1">
                    <span class="badge rounded-pill fw-normal <?= $vetted ? 'text-bg-success' : 'border bg-body text-body-secondary' ?>"
                          title="<?= h($vetted ? __('The MISP project has vetted this community') : __('The MISP project has not vetted this community')) ?>">
                        <i class="fas <?= $vetted ? 'fa-circle-check' : 'fa-circle-question' ?> me-1"></i><?= $vetted ? __('Vetted by the MISP project') : __('Not vetted') ?>
                    </span>
                </span>
            </div>
            <?php if (trim($data['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 border-primary bg-primary-subtle bg-opacity-25 rounded-end px-3 py-2 text-break">
                    <?= nl2br(h($data['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
            <?php if ($url !== ''): ?>
                <div class="d-flex align-items-stretch border rounded-pill bg-body-tertiary font-monospace overflow-hidden lh-base mw-100 mt-2" style="width:fit-content;">
                    <?php if ($isLink): ?>
                        <a class="d-inline-flex align-items-center gap-1 px-2 text-truncate text-decoration-none small"
                           href="<?= h($url) ?>" rel="noreferrer noopener" target="_blank" title="<?= h(__('Website')) ?>: <?= h($url) ?>">
                            <i class="fas fa-arrow-up-right-from-square opacity-50"></i><span class="text-truncate"><?= h($url) ?></span>
                        </a>
                    <?php else: ?>
                        <span class="d-inline-flex align-items-center gap-1 px-2 text-truncate small text-body-emphasis" title="<?= h($url) ?>">
                            <i class="fas fa-globe opacity-50"></i><span class="text-truncate"><?= h($url) ?></span>
                        </span>
                    <?php endif; ?>
                    <span class="vr my-1"></span>
                    <button type="button" class="ov-copy-target focus-ring d-inline-flex align-items-center border-0 bg-transparent text-body-secondary px-2 mb-0"
                            title="<?= h(__('Copy the URL')) ?>" aria-label="<?= h(__('Copy the URL')) ?>"
                            data-copy-value="<?= h($url) ?>" data-copy-msg="<?= h(__('URL copied to clipboard')) ?>"
                            onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">
                        <i class="fas fa-copy fa-xs opacity-100 text-body-emphasis"></i>
                    </button>
                </div>
            <?php endif; ?>
        </div>

        <?php if (trim($data['scope_of_data_to_be_shared'] ?? '') !== ''): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('What is shared') ?></div>
                <div class="small text-break"><?= nl2br(h($data['scope_of_data_to_be_shared'])) ?></div>
            </div>
        <?php endif; ?>

        <?php
        // Line one: who runs it and how to get in; line two: what it is about.
        $firstLine = [
            ['label' => __('Who'), 'html' => $hostTile],
        ];
        foreach ($joiningTiles as $i => $tile) {
            $firstLine[] = ['label' => $i === 0 ? __('Joining') : '', 'html' => $tile];
        }
        ?>
        <div class="d-flex flex-column gap-2">
            <div class="row row-cols-1 row-cols-md-3 g-2">
                <?php foreach ($firstLine as $cell): ?>
                    <div class="col">
                        <div class="<?= $labelClass ?> mb-1<?= $cell['label'] === '' ? ' invisible d-none d-md-block' : '' ?>" style="<?= $labelStyle ?>">
                            <?= $cell['label'] === '' ? '&nbsp;' : h($cell['label']) ?>
                        </div>
                        <?= $cell['html'] ?>
                    </div>
                <?php endforeach; ?>
            </div>
            <?php if (!empty($factTiles)): ?>
                <div class="row row-cols-1 row-cols-md-3 g-2">
                    <?php foreach ($factTiles as $tile): ?>
                        <div class="col"><?= $tile ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <?php if ($pgpKey !== ''): ?>
            <details>
                <summary class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="fas fa-key me-1 opacity-75"></i><?= __('PGP key') ?>
                </summary>
                <div class="position-relative mt-1">
                    <button type="button" class="ov-copy-target btn btn-sm btn-light border position-absolute top-0 end-0 m-2"
                            title="<?= h(__('Copy the PGP key')) ?>" aria-label="<?= h(__('Copy the PGP key')) ?>"
                            data-copy-value="<?= h($pgpKey) ?>" data-copy-msg="<?= h(__('PGP key copied to clipboard')) ?>"
                            onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">
                        <i class="fas fa-copy opacity-100 text-dark"></i>
                    </button>
                    <pre class="mb-0 p-3 pe-5 small bg-body-tertiary border rounded overflow-auto" style="max-height:14rem;white-space:pre-wrap;word-break:break-all;"><?= h($pgpKey) ?></pre>
                </div>
            </details>
        <?php endif; ?>

    </div>
</div>
