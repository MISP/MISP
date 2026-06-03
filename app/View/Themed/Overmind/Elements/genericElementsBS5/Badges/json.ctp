<?php
/**
 * Expected:
 * $json (string|array) -> Le contenu JSON
 * $full (bool) -> Bloc complet ou juste une icône
 */
$json = $json ?? '{}';
if (is_string($json)) {
    $json = json_decode($json, true) ?: [];
}
$formattedJson = json_encode($json, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
$full = $full ?? true;
?>

<div class="d-flex align-items-center">
    <?php if ($full): ?>
        <div class="position-relative w-100">
            <div class="bg-white border p-3 rounded small mb-2">
                <pre class="mb-0 small" style="overflow-x: auto;"><code><?= h($formattedJson) ?></code></pre>

                <button class="btn btn-sm btn-outline-dark border-0 position-absolute top-0 end-0 m-2 opacity-50 hover-opacity-100 copy-json-btn"
                    data-json="<?= h($formattedJson) ?>"
                    title="<?= __('Copy JSON') ?>">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
        </div>

    <?php else: ?>
        <div class="cursor-pointer" 
             data-bs-toggle="tooltip" 
             data-bs-html="true" 
             title="<pre class='text-start small mb-0'><?= h(mb_strimwidth($formattedJson, 0, 200, '...')) ?></pre>">
            <i class="fas fa-file-code text-primary"></i>
        </div>
    <?php endif; ?>
</div>

<style>
    .shadow-inner { box-shadow: inset 0 2px 4px rgba(0,0,0,0.3); }
    .hover-opacity-100:hover { opacity: 1 !important; }
</style>

<script>
document.addEventListener('click', function(e) {
    const btn = e.target.closest('.copy-json-btn');
    if (!btn) return;
    const text = btn.getAttribute('data-json');
    copyToClipboard(btn, text);
});
</script>