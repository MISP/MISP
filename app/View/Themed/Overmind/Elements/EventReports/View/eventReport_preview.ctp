<?php

$reportData = $data['EventReport'] ?? [];
$content    = $reportData['content'] ?? '';
$reportId   = (int)($reportData['id'] ?? 0);
$hasContent = ($content !== '' && $content !== null);

?>

<div class="card shadow-sm mb-3" style="height:50vh; overflow-y:auto;">
    <?php if ($hasContent): ?>
    <div class="card-body p-3">
        <div id="er-preview-readonly"
             class="markdown-preview-body">
        </div>
    </div>

    <script>
    (function () {
        var raw = <?= json_encode($content) ?>;
        document.addEventListener('DOMContentLoaded', function () {
            var target = document.getElementById('er-preview-readonly');
            if (!target) { return; }

            function render() {
                if (window.markdownit) {
                    var md = window.markdownit({
                        html: false, linkify: true, typographer: true
                    });
                    target.innerHTML = md.render(raw);
                } else {
                    /* markdown-it not yet ready — retry once */
                    setTimeout(render, 100);
                }
            }
            render();
        });
    })();
    </script>

    <?php else: ?>
    <div class="card-body d-flex flex-column align-items-center justify-content-center text-muted py-5">
        <i class="fas fa-file-slash fa-2x mb-3 opacity-50"></i>
        <p class="mb-1 fw-semibold"><?= __('No content') ?></p>
        <p class="small mb-0">
            <?= __('This report has no content yet.') ?>
            <?php if (!empty($canEdit)): ?>
                <?= __('Use the') ?>
                <a href="#tab-content"
                   onclick="bootstrap.Tab.getOrCreateInstance(document.querySelector('[href=\'#tab-content\']')).show()">
                    <?= __('Edit Content') ?>
                </a>
                <?= __('tab to add some.') ?>
            <?php endif; ?>
        </p>
    </div>
    <?php endif; ?>

</div>
