<?php
/**
 * The way to the Objects tab, filtered to one template (the tab filters on
 * one at a time).
 *
 * @var string $template
 * @var int $total objects of that template the reader may see
 * @var bool $long say "all N" rather than "N"
 */
$total = (int)$total;
$count = !empty($long) && $total > 1
    ? sprintf(__('all %s'), number_format($total)) : number_format($total);
?>
<button type="button" class="eov-objbtn" data-eov-objects="<?= h($template) ?>"
        title="<?= h(sprintf(__('Open the Objects tab filtered to %s'),
            $template)) ?>">
    <i class="misp-icon misp-icon-object misp-simple" aria-hidden="true"></i>
    <span class="eov-objbtn-t"><?= h($template) ?></span>
    <span class="eov-objbtn-n"><?= h($count) ?></span>
    <i class="fas fa-arrow-right" aria-hidden="true"></i>
</button>
