<?php
/**
 * A `button` child of the filter bar. `pressed` makes a toggle: the url is
 * then where pressing it leads, on or off.
 *
 * @var array $child
 * @var bool $nav whether index-filters.js loads the link in place
 */
?>
<a href="<?= h($child['url']) ?>"
   class="<?= h($child['class']) ?> flex-shrink-0<?= !empty($child['pressed']) ? ' active' : '' ?>"<?php
   if (array_key_exists('pressed', $child)): ?>
   aria-pressed="<?= !empty($child['pressed']) ? 'true' : 'false' ?>"<?php
   endif; ?><?php
   if (!empty($child['id'])): ?>
   id="<?= h($child['id']) ?>"<?php
   endif; ?><?php
   if (!empty($nav) && empty($child['onclick']) && !preg_match('/^(#|javascript:)/i', (string)$child['url'])): ?>
   data-ifp-nav data-ifp-swap="<?= h($child['id'] ?? 'toggle-' . substr(md5((string)($child['label'] ?? '')), 0, 8)) ?>"<?php
   endif; ?><?php
   if (!empty($child['title'])): ?>
   title="<?= h($child['title']) ?>"<?php
   endif; ?><?php
   if (!empty($child['onclick'])): ?>
   onclick="<?= h($child['onclick']) ?>"<?php
   endif; ?>>
    <?php if (!empty($child['icon'])): ?>
        <i class="<?= h($child['icon']) ?>"></i>
    <?php endif; ?>
    <?= h($child['label']) ?>
</a>
