<?php
/*
 * report_preview.ctp — the opening of an event report, rendered and faded
 * out by event-report-reader.js as the event overview's report card is.
 * Only the beginning travels with the page: enough to fill the clamp, cut at
 * a line, and never inside a code fence, so a diagram stays drawable.
 */
$reportId = (int)Hash::get($row, 'EventReport.id');
$content = (string)Hash::get($row, 'EventReport.content');
$limit = 3000;

$snippet = $content;
if (strlen($content) > $limit && preg_match('/^.{0,' . $limit . '}/su', $content, $head)) {
    $snippet = $head[0];
    $lineEnd = strrpos($snippet, "\n");
    if ($lineEnd !== false && $lineEnd > $limit / 2) {
        $snippet = substr($snippet, 0, $lineEnd);
    }
    // A fence left open runs to its close when that is near, else is left out.
    if (preg_match_all('/^[ \t]*(?:```|~~~)/m', $snippet, $fences, PREG_OFFSET_CAPTURE) % 2 === 1) {
        $opened = end($fences[0])[1];
        if (preg_match('/\n[ \t]*(?:```|~~~)[^\n]*/', $content, $close, PREG_OFFSET_CAPTURE, strlen($snippet))
            && $close[0][1] < $limit * 8) {
            $snippet = substr($content, 0, $close[0][1] + strlen($close[0][0]));
        } elseif ($opened > 0) {
            $snippet = substr($snippet, 0, $opened);
        }
    }
}
?>
<?php if (trim($snippet) === ''): ?>
    <p class="eo-report-snippet-empty"><?= __('This report has no content yet.') ?></p>
<?php else: ?>
    <div class="eo-report-snippet"
         data-report-preview="<?= $reportId ?>"
         data-report-event="<?= (int)Hash::get($row, 'EventReport.event_id') ?>"
         data-report-content="<?= h($snippet) ?>">
        <div class="eo-report-clamp">
            <div class="markdown-preview-body" data-report-preview-body>
                <div class="text-center py-3"><div class="misp-loader misp-loader-sm" role="status"></div></div>
            </div>
        </div>
    </div>
    <button type="button" class="btn btn-link btn-sm eo-report-snippet-read"
            data-report-read="<?= $reportId ?>">
        <i class="fas fa-book-open me-1"></i><?= __('Read in full') ?>
    </button>
<?php endif; ?>
