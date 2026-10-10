<?php
/*
 * The organisation's identity card, built like the user view's: an aside
 * holding the logo (or a glyph when there is none) beside the field table.
 * The aside is tinted by whether the organisation is local or remote.
 */

$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$fullAccess = $this->viewVars['fullAccess'] ?? false;
$org = $data['Organisation'] ?? [];
$local = !empty($org['local']);

$dash = '<span class="text-muted">&mdash;</span>';
$tone = $local ? 'success' : 'secondary';
$logo = $this->OrgImg->getOrgLogoV2($org, 72, false);

$scopePill = $local
    ? '<span class="badge rounded-pill text-bg-success d-inline-flex align-items-center gap-1">'
        . '<i class="fas fa-house"></i>' . __('Local') . '</span>'
    : '<span class="badge rounded-pill text-bg-light border d-inline-flex align-items-center gap-1 fw-normal text-muted">'
        . '<i class="fas fa-globe"></i>' . __('Remote') . '</span>';

// ── ID —
$idHtml = isset($org['id']) && $org['id'] !== ''
    ? '<span class="bg-light border rounded px-2 py-1 fw-semibold small font-monospace">#' . h($org['id']) . '</span>'
    : $dash;

// ── UUID — monospace chip + copy button
$uuid = $org['uuid'] ?? '';
if ($uuid !== '') {
    $uuidHtml = '<span class="d-inline-flex align-items-center gap-1 bg-light border rounded px-2 py-1">'
        . '<span class="font-monospace small">' . h($uuid) . '</span>'
        . '<button type="button" class="text-muted border-0 bg-transparent p-0 ms-1" '
        . 'data-copy-value="' . h($uuid) . '" '
        . 'data-copy-msg="' . h(__('UUID copied to clipboard')) . '" '
        . 'onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)" '
        . 'data-bs-toggle="tooltip" title="' . h(__('Copy UUID')) . '" aria-label="' . h(__('Copy UUID')) . '">'
        . '<i class="fas fa-copy fa-xs"></i></button>'
        . '</span>';
} else {
    $uuidHtml = $dash;
}

// ── Type — bordered badge
$type = trim($org['type'] ?? '');
$typeHtml = $type !== ''
    ? '<span class="border border-dark rounded px-2 py-1 small">' . h($type) . '</span>'
    : $dash;

// ── Local — coloured yes/no.
$localHtml = $local
    ? '<span class="text-success fw-semibold"><i class="fas fa-circle-check me-1"></i>' . __('Yes') . '</span>'
    : '<span class="text-muted"><i class="fas fa-circle-xmark me-1"></i>' . __('No') . '</span>';

// ── Domain restrictions — "@domain" chips, dash if none.
$domains = $org['restricted_to_domain'] ?? [];
if (!is_array($domains)) {
    $domains = preg_split('/[\r\n,]+/', trim((string)$domains), -1, PREG_SPLIT_NO_EMPTY);
}
$domains = array_values(array_filter(array_map('trim', $domains), function ($d) {
    return $d !== '';
}));
if (empty($domains)) {
    $domainsHtml = $dash;
} else {
    $domainsHtml = '<span class="d-inline-flex flex-wrap gap-1 justify-content-end">';
    foreach ($domains as $domain) {
        $domainsHtml .= '<span class="badge text-bg-light border font-monospace">'
            . '<i class="fas fa-at me-1 text-muted"></i>' . h($domain) . '</span>';
    }
    $domainsHtml .= '</span>';
}

// ── Nationality (declared string) and Country (flag + ISO code) as distinct rows.
$nationality = trim($org['nationality'] ?? '');
$nationalityHtml = $nationality !== '' ? h($nationality) : $dash;

$countryCode = $org['country_code'] ?? '';
$flag = $countryCode ? $this->Icon->countryFlag($countryCode, $nationality) : '';
$countryHtml = $flag !== ''
    ? '<span class="d-inline-flex align-items-center gap-2 justify-content-end">' . $flag . '<span>' . h(strtoupper($countryCode)) . '</span></span>'
    : $dash;

$sector = trim($org['sector'] ?? '');
$sectorHtml = $sector !== '' ? h($sector) : $dash;

//Friendly time display
$timeHtml = function ($value, $icon) use ($dash) {
    if (empty($value)) {
        return $dash;
    }
    return '<span class="d-inline-flex align-items-center gap-2 justify-content-end text-nowrap">'
        . '<i class="fas fa-' . $icon . ' text-muted"></i>'
        . $this->Time->time($value)
        . '</span>';
};

// Ordered rows
$meta = [];
$meta[] = ['label' => __('ID'), 'html' => $idHtml];
$meta[] = ['label' => __('UUID'), 'html' => $uuidHtml];
$meta[] = ['label' => __('Type'), 'html' => $typeHtml];
$meta[] = ['label' => __('Local'), 'html' => $localHtml];
$meta[] = ['label' => __('Sector'), 'html' => $sectorHtml];
$meta[] = ['label' => __('Nationality'), 'html' => $nationalityHtml];
$meta[] = ['label' => __('Country'), 'html' => $countryHtml];
$meta[] = ['label' => __('Domain restrictions'), 'html' => $domainsHtml];

if ($isSiteAdmin || $fullAccess) {
    if (!empty($org['created_by_email'])) {
        $meta[] = ['label' => __('Created by'), 'html' => '<span class="text-nowrap"><i class="fas fa-user-plus text-muted me-2"></i>' . h($org['created_by_email']) . '</span>'];
    }
    if (!empty($org['date_created'])) {
        $meta[] = ['label' => __('Creation time'), 'html' => $timeHtml($org['date_created'], 'calendar-plus')];
    }
    if (!empty($org['date_modified'])) {
        $meta[] = ['label' => __('Last modified'), 'html' => $timeHtml($org['date_modified'], 'clock-rotate-left')];
    }
}
?>
<div class="card shadow-sm mb-3 overflow-hidden">
    <div class="row g-0">

        <!-- ASIDE — the logo -->
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

        <!-- FIELDS -->
        <div class="col">
            <table class="table align-middle mb-0">
                <tbody>
                    <?php foreach ($meta as $row): ?>
                        <tr>
                            <th scope="row" class="text-dark fw-semibold p-3 text-nowrap w-25">
                                <?= h($row['label']) ?>
                            </th>
                            <td class="text-end pe-3">
                                <?= $row['html'] ?? h($row['value'] ?? '') ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

    </div>
</div>
