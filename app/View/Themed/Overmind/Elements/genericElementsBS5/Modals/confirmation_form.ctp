<?php
/*
 * confirmation_form.ctp — generic "are you sure?" modal for an action that
 * needs a real POST (so the form is server-rendered and carries a valid token).
 *
 * Dressed in the shared modal chrome: Forms/modal_header for the accented
 * strip, Forms/modal_footer for the action bar. The accent is read from
 * $submitClass when a caller only says `btn btn-danger`, so the strip, the
 * glyphs and the submit button end up one colour without every call site
 * having to name a scope.
 *
 * Expected:
 *   $title        => modal heading
 *   $model        => model name for Form->create
 *   $url          => POST target
 *   $message      => the question
 * Optional:
 *   $hiddenField  => name of the hidden field carrying the payload (default 'id');
 *                    false when the payload already travels in the POST URL
 *   $submitLabel  => submit button label (default Yes)
 *   $submitIcon   => Font Awesome icon name without the "fa-" prefix; it also
 *                    becomes the header's watermark glyph
 *   $submitClass  => full class attribute of the submit button, for a colour the
 *                    accent table has no name for — prefer $accent
 *   $submitLabelHtml => raw HTML for the submit button instead of
 *                    $submitLabel / $submitIcon, for a label JavaScript rewrites
 *                    through an inner element — carry your own glyph, and escape
 *                    it yourself
 *   $accent       => accent key, see ModalAccent; defaults to the scope
 *                    $submitClass names, then 'primary'
 *   $eyebrow      => small uppercase label above the title (default Confirmation)
 *   $description  => muted one-liner under the title
 *   $titleIcon    => full class attribute of the glyph left of the title
 *   $icon         => full class attribute of the right-hand watermark glyph
 *   $warning      => a cautionary line, or an array of them, rendered as a
 *                    callout under the question
 *   $bodyHtml     => raw HTML between the question and the warning, for the few
 *                    confirmations that show what they are about to act on (the
 *                    event publish modal lists the servers) — escape it yourself
 *   $hint         => muted line in the footer, left of the buttons
 *   $meta         => footer chips instead of $hint, each ['label' =>, 'id' =>]
 *   $canProceed   => false to drop the submit button, leaving only a way out
 *                    (nothing in the selection is actionable)
 *   $escape       => h() the question and the warnings (default true — pass
 *                    false for a message that emphasises its subject)
 */
$hiddenField = $hiddenField ?? 'id';
$submitLabel = $submitLabel ?? __('Yes');
$submitIcon = $submitIcon ?? null;
$canProceed = !isset($canProceed) || $canProceed;
$escape = !isset($escape) || $escape;
$eyebrow = $eyebrow ?? __('Confirmation');

/* `btn btn-danger` names a scope this theme already knows, so a caller that
 * only colours its submit button still gets the matching header strip. A class
 * the table has no name for reaches the button untouched, minus the plain `btn`
 * the footer adds itself. */
$submitClass = $submitClass ?? null;
$namedAccent = null;
if ($submitClass !== null
    && preg_match('/\bbtn-([a-zA-Z]+)\b/', $submitClass, $matches)
    && in_array($matches[1], $this->ModalAccent->keys(), true)
) {
    $namedAccent = $matches[1];
}
$accent = $accent ?? ($namedAccent ?? 'primary');

$submitSpec = [
    'label' => $submitLabel,
    'icon' => $submitIcon === null ? 'fas fa-check' : 'fas fa-' . $submitIcon,
    'type' => 'submit',
];
if ($submitClass !== null && $namedAccent === null) {
    $submitSpec['class'] = trim(preg_replace('/(^|\s)btn(\s|$)/', ' ', $submitClass));
}

/* A label the modal's own script rewrites — the raw HTML brings its own glyph,
 * so the spec's icon steps aside. */
if (!empty($submitLabelHtml)) {
    $submitSpec['labelHtml'] = $submitLabelHtml;
    $submitSpec['icon'] = '';
}

/* A dialog with nothing to act on is an explanation rather than a question, and
 * a destructive one warns instead of asking. */
$titleIcon = $titleIcon ?? (!$canProceed
    ? 'fas fa-circle-info'
    : (in_array($accent, ['danger', 'warning'], true)
        ? 'fas fa-triangle-exclamation'
        : 'fas fa-circle-question'));
$icon = $icon ?? ($canProceed && $submitIcon !== null ? 'fas fa-' . $submitIcon : $titleIcon);

/* One line or several — the callers that collect their own reasons pass an
 * array rather than pre-joining it into a paragraph. */
$warnings = array_values(array_filter(
    (array)($warning ?? []),
    function ($line) {
        return $line !== null && $line !== '';
    }
));

$text = function ($value) use ($escape) {
    return $escape ? h($value) : $value;
};
?>
<!-- The modal body it lands in has no padding and does not clip, so the strip
     is rounded here rather than squaring off the dialog's corners. -->
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => $accent,
        'eyebrow' => $eyebrow,
        'title' => $title,
        'description' => $description ?? '',
        'titleIcon' => $titleIcon,
        'icon' => $icon,
    ]) ?>

    <?php
    echo $this->Form->create($model, [
        'id' => 'PromptForm',
        'url' => $url,
        'class' => 'm-0',
    ]);
    if ($hiddenField !== false) {
        echo $this->Form->hidden($hiddenField);
    }
    ?>

    <div class="px-4 py-4 d-flex flex-column gap-3">
        <p class="mb-0 lh-base"><?= $text($message) ?></p>

        <?php if (!empty($bodyHtml)): ?>
            <?= $bodyHtml ?>
        <?php endif; ?>

        <?php if (!empty($warnings)): ?>
            <div class="d-flex gap-2 p-3 rounded-2 bg-warning-subtle text-warning-emphasis border-start border-3 border-warning"
                 role="note">
                <i class="fas fa-triangle-exclamation" style="font-size:.8rem; margin-top:.15rem;"></i>
                <div class="lh-base" style="font-size:.8rem;">
                    <?php if (count($warnings) === 1): ?>
                        <?= $text($warnings[0]) ?>
                    <?php else: ?>
                        <ul class="mb-0 ps-3">
                            <?php foreach ($warnings as $line): ?>
                                <li><?= $text($line) ?></li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => $accent,
        'bleed' => true,
        'align' => (empty($hint) && empty($meta)) ? 'end' : 'between',
        'hint' => $hint ?? '',
        'meta' => $meta ?? [],
        'cancel' => [
            'label' => $canProceed ? __('Cancel') : __('Close'),
            'icon' => 'fas fa-xmark',
        ],
        'submit' => $canProceed ? $submitSpec : false,
    ]) ?>

    <?= $this->Form->end() ?>
</div>
