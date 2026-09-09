<?php
/*
 * The key-server result list for the user forms.
 *
 * UsersController::searchGpgKey renders this with the layout off, and
 * initPgpKeyLookup() in mispOvermind.js drops it straight under the PGP field
 * of the form that asked for it. It is therefore a fragment and not a modal —
 * no chrome elements — and it carries no script of its own: injected HTML never
 * runs its own <script>, so the form delegates the row clicks instead. Each row
 * only has to hand back a fingerprint through `data-pgp-fingerprint`.
 *
 * $keys  array  each ['fingerprint' =>, 'key_id' =>, 'date' =>, 'address' =>]
 */
?>
<div class="border rounded-3 overflow-hidden">
    <div class="d-flex align-items-start gap-2 px-3 py-2 border-bottom"
         style="background:rgba(255,193,7,.08); font-size:.75rem;">
        <i class="fas fa-triangle-exclamation text-warning mt-1"></i>
        <div class="flex-grow-1">
            <?= __('Anyone can upload a key to a key server. Check the whole fingerprint against another source before keeping it — the key ID alone proves nothing.') ?>
            <a href="https://evil32.com" rel="noreferrer noopener" target="_blank" class="text-decoration-none text-nowrap">
                <?= __('Why') ?> <i class="fas fa-up-right-from-square" style="font-size:.6rem;"></i>
            </a>
        </div>
        <button type="button" class="btn-close flex-shrink-0" style="font-size:.6rem;"
                data-pgp-dismiss aria-label="<?= __('Close') ?>"></button>
    </div>
    <div class="list-group list-group-flush">
        <?php foreach ($keys as $key): ?>
            <?php
            $meta = array_filter([
                $key['key_id'] ?? '',
                $key['date'] ?? '',
                empty($key['address']) ? '' : str_replace("\n", ', ', trim($key['address'])),
            ]);
            ?>
            <button type="button"
                    class="list-group-item list-group-item-action d-flex align-items-center gap-3 text-start"
                    data-pgp-fingerprint="<?= h($key['fingerprint']) ?>"
                    title="<?= h(__('Use this key')) ?>">
                <i class="fas fa-key text-primary flex-shrink-0"></i>
                <span class="flex-grow-1" style="min-width:0;">
                    <code class="text-body d-block" style="font-size:.75rem;"><?= h(chunk_split($key['fingerprint'], 4, ' ')) ?></code>
                    <span class="text-muted d-block text-truncate" style="font-size:.7rem;"><?= h(implode(' · ', $meta)) ?></span>
                </span>
                <i class="fas fa-arrow-right text-muted flex-shrink-0" style="font-size:.7rem;"></i>
            </button>
        <?php endforeach; ?>
    </div>
</div>
