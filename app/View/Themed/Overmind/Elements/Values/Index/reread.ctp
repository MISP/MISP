<?php
/**
 * *Read my paste the other way* — the one control that makes the
 * extraction mode safe to offer.
 *
 * The extractor types about half of what a MISP instance holds
 * (`value-index.md` §11.2), so a reader whose `mutex`, `cpe` or
 * `user-agent` did not come back needs a way to say *no, these are my
 * values*. The reverse is the same button pointing the other way: a
 * worklist full of sentences is a paste the page read as a list and
 * should have read as text.
 *
 * **Its own form, and a real one.** `FormHelper` hashes a field list
 * together with the action it posts to, and this is rendered inside a
 * fragment `triage()` returned — the same reason the comma offer
 * above it carries its own form. The cost is the reader's paste twice
 * in the document; the gain is that the way back works with no script
 * at all, which is exactly the condition under which the rest of this
 * page degrades to a plain list.
 *
 * @var int $extract 1 to read the paste as text, 0 to read its lines
 * @var string $label What the button says
 * @var string|null $note A line before it, or null
 */
?>
<div class="vi-reread">
<?php if (!empty($note)): ?>
    <span class="vi-mark"><?= h($note) ?></span>
<?php endif; ?>
<?php
echo $this->Form->create('Value', array(
    'class' => 'vi-reread__form',
    'url' => $this->Html->url(array(
        'controller' => 'values',
        'action' => 'resolve',
    )),
));
echo $this->Form->hidden('value', array(
    'value' => isset($this->request->data['Value']['value'])
        ? $this->request->data['Value']['value']
        : '',
));
echo $this->Form->hidden('extract', array('value' => (int)$extract));
?>
    <button type="submit" class="vi-btn"><?= h($label) ?></button>
<?= $this->Form->end() ?>
</div>
