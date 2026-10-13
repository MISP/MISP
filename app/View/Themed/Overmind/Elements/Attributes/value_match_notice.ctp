<?php
/**
 * How the global attribute index matched the value it was given, and the
 * other way one press away.
 *
 * @var string $mode 'words' (value_search) or 'contains' (value)
 * @var string $term
 * @var string $switchUrl the same index, matched the other way
 */
$words = $mode === 'words';
?>
<div class="d-flex flex-wrap align-items-center gap-2 small mb-2 px-1" data-attr-value-match="<?= h($mode) ?>">
    <i class="fas <?= $words ? 'fa-font' : 'fa-asterisk' ?> text-body-secondary" aria-hidden="true"></i>
    <span class="text-body-secondary">
        <?= sprintf(
            h($words ? __('Values with a word that starts with %s') : __('Values containing %s anywhere')),
            '<span class="font-monospace fw-semibold text-body">' . h($term) . '</span>'
        ) ?>
    </span>
    <span class="text-body-tertiary" aria-hidden="true">&middot;</span>
    <a class="link-primary fw-semibold text-decoration-none"
       href="<?= h($switchUrl) ?>"
       title="<?= h($words
           ? __('Also finds it inside a word, such as paypal in theverifypaypal.com. Slower: every stored value is read.')
           : __('Faster, through the search index, but misses it inside a word.')) ?>">
        <?= h($words ? __('Search inside words too') : __('Only where a word starts with it')) ?>
    </a>
</div>
