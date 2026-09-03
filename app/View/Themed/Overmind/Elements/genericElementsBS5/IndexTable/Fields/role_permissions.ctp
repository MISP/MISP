<?php
/*
 * role_permissions.ctp
 *
 * Compact "Permissions" cell. Replaces the historical one-boolean-column-per-flag
 * layout (24+ columns, horizontal scroll) with a single column that summarises the
 * role in one or two pills. Adding a new permission flag changes only the counter's
 * denominator, never the table's shape.
 *
 * Three cases:
 *   - Site admin  -> a single "Full access" pill: the flag implies every other one.
 *   - Org admin   -> an "Org Admin" pill next to the counter, since that flag is the
 *                    one that materially changes what the role can do.
 *   - Anything else -> just the counter.
 *
 * The counter carries a popover (hover or focus/click) listing every flag as granted
 * or denied, mirroring the "Permission flags" grid of Roles/view. It is created
 * lazily by the shared initialiser in mispOvermind.js so AJAX-paginated rows work,
 * and rendered into <body> so the table's overflow container cannot clip it.
 *
 * Expected:
 *   $field['data_path'] => path to the Role array (e.g. 'Role')
 *   $field['permFlags'] => Role::permFlags map (key => ['text', 'title', ...])
 */
$role = Hash::get($row, $field['data_path']);
if (empty($role)) {
    return;
}

$permFlags = $field['permFlags'] ?? [];

// Site admin implies every other permission, so a single prominent pill says it all.
if (!empty($role['perm_site_admin'])) {
    echo sprintf(
        '<span class="badge rounded-pill text-bg-danger fw-semibold" title="%s">'
            . '<i class="fas fa-shield-halved me-1"></i>%s</span>',
        h($permFlags['perm_site_admin']['title'] ?? ''),
        __('Full access')
    );
    return;
}

// perm_site_admin is off by definition here, so it is neither counted nor listed.
$flags = $permFlags;
unset($flags['perm_site_admin']);

$granted = 0;
$items = [];
foreach ($flags as $flag => $permFlag) {
    $on = !empty($role[$flag]);
    if ($on) {
        $granted++;
    }
    $items[] = sprintf(
        '<div class="rp-item%s" title="%s"><span class="rp-name">%s</span>'
            . '<i class="fas fa-%s rp-mark"></i></div>',
        $on ? ' rp-on' : '',
        h($permFlag['title'] ?? ''),
        h($permFlag['text'] ?? Inflector::humanize(substr($flag, 5))),
        $on ? 'check' : 'xmark'
    );
}
$total = count($flags);

$popover = sprintf(
    '<div class="rp-head">%s</div><div class="rp-grid">%s</div>',
    __('%s of %s permissions granted', $granted, $total),
    implode('', $items)
);
?>
<span class="d-inline-flex flex-wrap align-items-center gap-1">
    <?php if (!empty($role['perm_admin'])): ?>
        <span class="badge rounded-pill bg-primary fw-semibold"
              title="<?= h($flags['perm_admin']['title'] ?? '') ?>">
            <i class="fas fa-user-shield me-1"></i><?= __('Org Admin') ?>
        </span>
    <?php endif; ?>

    <span class="badge rounded-pill border text-bg-light role-perm-counter <?= $granted ? 'text-body' : 'text-body-secondary' ?>"
          role="button"
          tabindex="0"
          aria-label="<?= h(__('%s of %s permissions granted', $granted, $total)) ?>"
          data-bs-toggle="popover"
          data-bs-html="true"
          data-bs-trigger="hover focus"
          data-bs-custom-class="role-perm-popover"
          data-bs-content="<?= h($popover) ?>">
        <i class="fas fa-key me-1 opacity-75"></i><?= h($granted) ?><span class="opacity-50">/<?= h($total) ?></span>
    </span>
</span>
