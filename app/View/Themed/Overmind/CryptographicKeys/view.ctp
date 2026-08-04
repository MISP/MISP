<?php
/**
 * Overmind BS5 — inspect a cryptographic (signing) key.
 *
 * Rendered layout-less as a modal fragment (see
 * CryptographicKeysController::view, theme === 'Overmind' branch). The
 * controller pre-builds $html (an nl2br()'d, escaped <span class="quickSelect">
 * wrapping the key material) plus $title, matching the legacy
 * /genericTemplates/display output.
 */
?>
<div class="container">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-header">
                <h4 class="card-title mb-2 mt-2"><?= h($title) ?></h4>
            </div>

            <div class="card-body">
                <div class="font-monospace small text-break bg-body-tertiary border rounded p-3"
                     style="max-height: 60vh; overflow-y: auto;">
                    <?= empty($html) ? '' : $html ?>
                </div>
            </div>

            <div class="card-footer d-flex justify-content-end">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                    <?= __('Close') ?>
                </button>
            </div>

        </div>

    </div>

</div>
