<?php
// Only drawn when an admin set MISP.footermidleft, footermidright or footer_logo.
$footerText = array_filter([
    Configure::read('MISP.footermidleft'),
    Configure::read('MISP.footermidright'),
], 'strlen');
$footerLogo = Configure::read('MISP.footer_logo');
if (empty($footerText) && empty($footerLogo)) {
    return;
}
?>
<footer class="ov-footer">
    <?php if (!empty($footerText)): ?>
        <span><?= implode(' ', array_map('h', $footerText)) ?></span>
    <?php endif; ?>
    <?php if (!empty($footerLogo)): ?>
        <img src="<?= $this->Image->base64(APP . 'files/img/custom/' . $footerLogo) ?>"
            alt="<?= __('Footer logo') ?>"
            onerror="this.style.display='none';">
    <?php endif; ?>
</footer>
