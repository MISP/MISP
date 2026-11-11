<?php

$fromEventView = empty($report);
$reportData    = $data['EventReport'] ?? [];
$content       = $reportData['content'] ?? '';
$reportId      = (int)($reportData['id'] ?? 0);
$hasReport     = !empty($reportData);
$hasContent    = ($content !== '' && $content !== null);
$eventId       = (int)($reportData['event_id'] ?? ($data['Event']['id'] ?? 0));

$cardId    = 'er-preview-card-'    . ($reportId ?: 'main');
$bodyId    = 'er-preview-body-'    . ($reportId ?: 'main');
$overlayId = 'er-preview-overlay-' . ($reportId ?: 'main');
$maxH      = '300px';
/* Report view height (screen height minus fixed elements) */
$viewMaxH  = 'calc(100vh - 5rem)';
$canAddReport = $this->Acl->canModifyEvent($data);


$overlayHtml = '
<div id="' . h($overlayId) . '" class="er-preview-overlay" style="display:none;">
    <div class="er-preview-gradient"></div>
</div>';
?>

<?php if ($fromEventView): ?>
    <div class="card shadow-sm mb-3" id="report-card">
        <div class="p-3 border-bottom">
            <div class="d-flex align-items-center gap-3 flex-wrap">
                <div class="d-flex align-items-center gap-2 me-auto">
                    <div class="rounded-2 d-flex align-items-center justify-content-center"
                         style="width:36px;height:36px;background:#d4fcee;">
                        <span class="misp-icon misp-icon-report misp-simple" style="color:#10B981;font-size:1rem;"></span>
                    </div>
                    <div>
                        <div class="fw-bold lh-1"><?= __('First Event Report') ?></div>
                        <?php if ($hasReport): ?>
                            <div class="small text-muted mt-1">
                                <?= __('Created on %s', $this->Time->time($reportData['timestamp'])) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                <a href="#tab-reports"
                   class="btn btn-sm btn-outline-secondary ms-auto"
                   onclick="var t=document.querySelector('[href=\'#tab-reports\']');if(t){bootstrap.Tab.getOrCreateInstance(t).show();}return false;">
                    <i class="fas fa-list me-1"></i>
                    <?= __('All Reports') ?>
                </a>
            </div>
        </div>

        <?php if ($hasReport): ?>
            <div data-er-preview="<?= h($cardId) ?>"
                 data-er-preview-overlay="<?= h($overlayId) ?>"
                 data-er-preview-collapsed="<?= h($maxH) ?>">
                <div id="<?= h($cardId) ?>"
                     style="max-height:<?= $maxH ?>;overflow:hidden;">
                    <div class="card-body p-3">
                        <div id="<?= h($bodyId) ?>" class="markdown-preview-body"></div>
                    </div>
                </div>
                <?= $overlayHtml ?>
            </div>
        <?php else: ?>
            <div class="card-body d-flex flex-column align-items-center
                        justify-content-center text-muted py-5">
                <span class="misp-icon misp-icon-report misp-hexagone mb-2 opacity-50" style="font-size:2em;"></span>
                <p class="mb-1 fw-semibold small">
                    <?= __("This event doesn't have a report for the moment") ?>
                </p>
                <?php if ($canAddReport): ?>
                    <p class="small mb-0">
                        <a href="<?= h($baseurl . '/event_reports/add/' . ($data['Event']['id'] ?? '')) ?>"
                            onclick="event.preventDefault(); openModal('<?= h($baseurl . '/event_reports/add/' . ($data['Event']['id'] ?? '')) ?>');">
                                <?= __('Create the first report') ?>
                        </a>
                    </p>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

<?php elseif ($hasContent): ?>

    <div class="card shadow-sm mb-3"
         id="<?= h($cardId) ?>"
         data-center-on-click
         style="max-height:<?= $viewMaxH ?>;">
        <div class="card-body p-3 overflow-auto">
            <div id="<?= h($bodyId) ?>" class="markdown-preview-body"></div>
        </div>
    </div>

<?php else: ?>

    <div class="card shadow-sm mb-3">
        <div class="card-body d-flex flex-column align-items-center
                    justify-content-center text-muted py-5">
            <i class="fas fa-file-slash fa-2x mb-2 opacity-50"></i>
            <p class="mb-1 fw-semibold"><?= __('No content') ?></p>
            <p class="small mb-0">
                <?= __('This report has no content yet.') ?>
                <?php if (!empty($canEdit)): ?>
                    <?= __('Use the') ?>
                    <a href="#tab-content"
                       onclick="bootstrap.Tab.getOrCreateInstance(
                           document.querySelector('[href=\'#tab-content\']')
                       ).show()">
                        <?= __('Edit Content') ?>
                    </a>
                    <?= __('tab to add some.') ?>
                <?php endif; ?>
            </p>
        </div>
    </div>

<?php endif; ?>

<?php if ($hasContent || ($fromEventView && $hasReport)): ?>
<script>
(function () {
    var raw          = <?= json_encode($content) ?>;
    var bodyId       = <?= json_encode($bodyId) ?>;
    var cardId       = <?= json_encode($cardId) ?>;
    var overlayId    = <?= json_encode($overlayId) ?>;
    var reportId     = <?= json_encode($reportId) ?>;
    var eventId      = <?= json_encode($eventId) ?>;
    var templateVars = <?= json_encode($templateVariables ?? []) ?>;
    var renderer     = null;

    function checkOverflow() {
        var card    = document.getElementById(cardId);
        var overlay = document.getElementById(overlayId);
        if (!card || !overlay) { return; }
        if (card.scrollHeight > card.offsetHeight + 4) {
            overlay.style.display = 'block';
        }
    }

    function render(content) {
        var target = document.getElementById(bodyId);
        if (!target || !renderer) { return; }
        renderer.render(content, target);
        checkOverflow();
    }

    document.addEventListener('DOMContentLoaded', function () {
        if (!window.MispReportMarkdown) { return; }
        renderer = window.MispReportMarkdown.create({
            reportId: reportId,
            eventId: eventId,
            templateVariables: templateVars,
            invalidMessage: <?= json_encode(__('invalid scope or id')) ?>
        });
        renderer.ready.then(function () { render(raw); });

        document.addEventListener('misp:report-saved', function (event) {
            if (!event.detail || Number(event.detail.reportId) !== Number(reportId)) {
                return;
            }
            raw = event.detail.content;
            render(raw);
        });
    });

})();
</script>
<?php endif; ?>
