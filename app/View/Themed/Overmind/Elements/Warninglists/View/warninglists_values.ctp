<?php
$entries = $data['WarninglistEntry'] ?? [];
?>

<?php if (!empty($entries)): ?>

<div class="card mb-3 shadow-sm">

    <div class="card-body">

        <!-- HEADER -->
        <div class="d-flex justify-content-between align-items-center mb-3">
            <div class="text-muted small text-uppercase fw-bold">
                <?= __('Warninglist Values') ?>
            </div>
            
            <?= $this->element('genericElementsBS5/Badges/count',
                [
                    'count' => count($entries),
                ]
            ); ?>
        </div>

        <!-- SEARCH -->
        <input type="text"
               class="form-control mb-3"
               placeholder="<?= __('Search value...') ?>"
               onkeyup="filterWarninglist(this)">

        <!-- VALUES -->
        <div class="d-flex flex-wrap gap-2" id="warninglist-values">

            <?php foreach ($entries as $entry): ?>
                <span class="badge bg-light text-dark border value-item">
                    <?= h($entry['value']) ?>
                </span>
            <?php endforeach; ?>

        </div>

    </div>

</div>

<!-- FILTER SCRIPT -->
<script>
function filterWarninglist(input) {
    const filter = input.value.toLowerCase();
    const items = document.querySelectorAll('#warninglist-values .value-item');

    items.forEach(el => {
        const text = el.innerText.toLowerCase();
        el.style.display = text.includes(filter) ? '' : 'none';
    });
}
</script>

<?php endif; ?>