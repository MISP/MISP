<?php

$collection = $data['Collection'] ?? $data;

?>

<div class="card mb-3 shadow-sm">

    <div class="card-body">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small bold text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>

            <div class="fw-semibold fs-5">
                <?= h($collection['name'] ?? '') ?>
            </div>
        </div>

        <!-- DESCRIPTION -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Description') ?>
            </div>

            <div class="bg-light border rounded p-3">
                <?= nl2br(h($collection['description'] ?? '')) ?>
            </div>
        </div>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    ID
                </div>

                <div class="d-flex align-items-center gap-2">
                    <div class="bg-light rounded px-2 py-1">
                        <?= h($collection['id'] ?? '') ?>
                    </div>
                </div>
            </div>

            <!-- UUID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    UUID
                </div>

                <div class="d-flex align-items-center gap-2">

                    <div class="bg-light rounded px-2 py-1" id="uuid-value">
                        <?= h($collection['uuid'] ?? '') ?>
                    </div>

                    <!-- COPY BUTTON -->
                    <button
                        class="text-muted border-0 bg-white"
                        onclick="copyToClipboard('<?= h($collection['uuid'] ?? '') ?>')"
                        title="<?= __('Copy UUID') ?>"
                        aria-label="<?= __('Copy UUID') ?>">
                        <i class="fas fa-copy"></i>
                    </button>

                </div>
            </div>

            <!-- DISTRIBUTION -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Distribution') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/distribution',
                    [
                        'distribution' => $collection['distribution'],
                        'full' => true
                    ]
                ); ?>
            </div>

            <!-- CREATOR ORG -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Creator Org') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= $this->OrgImg->getOrgLogoV2($collection['Orgc'], 24, false); ?>
                    <?= h($collection['Orgc']['name'] ?? '') ?>
                </div>
            </div>

            <!-- OWNER ORG -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Owner Org') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= $this->OrgImg->getOrgLogoV2($collection['Org'], 24, false); ?>
                    <?= h($collection['Org']['name'] ?? '') ?>
                </div>
            </div>

            <!-- CREATED -->
            <div class="col-md-2">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Created at') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <i class="fas fa-calendar-alt text-muted"></i>
                    <?= !empty($collection['created']) ? $this->Time->time($collection['created']) : '' ?>
                </div>
            </div>

            <!-- MODIFIED -->
            <div class="col-md-2">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Modified at') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <i class="fas fa-history text-muted"></i>
                    <?= !empty($collection['modified']) ? $this->Time->time($collection['modified']) : '' ?>
                </div>
            </div>

        </div>

    </div>

</div>


<!-- COPY SCRIPT -->
<script>
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text);
    } else {
        // fallback
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
    }
}
</script>