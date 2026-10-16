<?php
/**
 * The invitation — what the region under the box says when it has
 * nothing else to say.
 *
 * It is an element rather than markup in `Values/index.ctp` because
 * the page needs it twice: once in the region, and once in a
 * `<template>` the script clones when the reader clears the page.
 * Two copies of a paragraph is two paragraphs to keep in step.
 */
?>
<div class="vi-invite">
    <div class="vi-tip" role="note">
        <i class="fas fa-lightbulb vi-tip__icon" aria-hidden="true"></i>
        <div>
            <h2 class="vi-tip__title"><?= h(__('Look up a value')) ?></h2>
            <p><?= h(__(
                'Enter a single value to open its Value Intelligence, or paste'
                . ' a list to get one row per value.'
            )) ?></p>
            <p><?= sprintf(
                h(__('Defanged input such as %s or %s is refanged'
                    . ' automatically.')),
                '<code>hxxp://</code>',
                '<code>1.2.3[.]4</code>'
            ) ?></p>
        </div>
    </div>
</div>
