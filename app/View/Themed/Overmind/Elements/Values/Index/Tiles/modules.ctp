<?php
/**
 * Enrichment modules the profile declares.
 *
 * The partner to the store tile: that one says what this organisation
 * has already asked, this one says how much there is to ask. Together
 * they are the whole of what a reader can expect from a value's
 * Enrichment tab before they open one.
 *
 * **Declared, not available, and the wording says so.** The count is
 * `ValueEnrichmentTool::planFor()`'s `declared` — the modules the
 * profile names across all the types it names them for. What a given
 * value's tab offers is that set met with this instance's enabled
 * modules and the value's own types, which is a second question and a
 * `GET /modules` away. Asking it here would put a network call on
 * every load of this page to qualify a number nobody has acted on yet,
 * so the tile promises only what it knows.
 *
 * Free: the declaration is part of the profile phase 7 resolved.
 *
 * @var int $modules
 */
?>
<div class="vi-tile" data-vi-tile="modules">
    <div class="vi-tile__label"><i class="fas fa-puzzle-piece vi-tile__icon" aria-hidden="true"></i><?= h(__('Enrichment modules')) ?></div>
<?php if ($modules === 0): ?>
    <div class="vi-tile__value vi-tile__value--none">
        <?= h(__('None declared')) ?>
    </div>
    <div class="vi-tile__sub"><?= h(__(
        'the active analyst profile lists no module, so nothing runs'
        . ' automatically on a value\'s Enrichment tab.'
    )) ?></div>
<?php else: ?>
    <div class="vi-tile__value"><?= h(number_format($modules)) ?></div>
    <div class="vi-tile__sub"><?= sprintf(
        h(__(
            '%s listed in the active analyst profile, offered on a'
            . ' value\'s Enrichment tab when enabled for its type.'
        )),
        h(__n('module', 'modules', $modules))
    ) ?></div>
<?php endif; ?>
</div>
