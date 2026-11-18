<?php
/*
 * A note's text, or an opinion's stance and comment, drawn as the analyst
 * data threads draw them (AnalystData/thread, analyst-rail.css): line breaks
 * kept, three lines then "Read more".
 *
 * Config:
 *   $field['data_path']    — Hash path to the text (e.g. 'Note.note')
 *   $field['opinion_path'] — Hash path to an opinion's score, to draw its gauge
 */
$text = (string)Hash::get($row, $field['data_path'] ?? '');
$opinion = isset($field['opinion_path']) ? Hash::get($row, $field['opinion_path']) : null;
if ($text === '' && $opinion === null) {
    echo '<span class="text-body-secondary">&mdash;</span>';
    return;
}
?>
<div class="adr-card adr-cell" data-adr-read-more="<?= h(__('Read more')) ?>" data-adr-read-less="<?= h(__('Read less')) ?>">
    <?php if ($opinion !== null): ?>
        <?= $this->element('AnalystData/stance', ['score' => $opinion]) ?>
    <?php endif; ?>
    <?php if ($text !== ''): ?>
        <p class="adr-text adr-clamp" dir="auto"><?= h($text) ?></p>
    <?php endif; ?>
</div>
