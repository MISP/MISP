<?php
/*
 * The line that says a page shows data held elsewhere — a feed, a remote
 * instance — above the content it is about.
 *
 *   $message  string  HTML; escape what it quotes yourself
 */
?>
<div class="alert alert-warning d-flex align-items-center gap-2 shadow-sm py-2" role="alert">
    <i class="fas fa-satellite-dish fs-4" aria-hidden="true"></i>
    <div><?= $message ?></div>
</div>
