<div class="container-fluid bg-dark text-white-50 expansion" style="z-index:2">
    <!-- Shortcut Toggle -->
    <div id="triangle" title="<?= __('Show keyboard shortcuts help') ?>"></div>

    <!-- Shortcut List -->
    <div class="shortcutsListContainer <?php echo $debugMode == 'debugOn' ? 'd-none': ''; ?>">
        <div>
            <?= __('Keyboard shortcuts for this page') ?>:<br>
            <div id="shortcuts"><?php echo __('none'); ?></div>
        </div>
    </div>

    <!-- Footer Content -->
    <footer class="row align-items-center text-center my-3">
        <!-- Left section: Downloads -->
        <div class="col text-start">
            <?php
            $gpgpath = ROOT.DS.APP_DIR.DS.WEBROOT_DIR.DS.'gpg.asc';
            if (Configure::read("MISP.download_gpg_from_homedir")) { ?>
                <span>Download: <?= $this->Html->link(__('Server PGP public key'), ['controller' => 'users', 'action' => 'getGpgPublicKey']) ?></span>
            <?php } elseif (file_exists($gpgpath) && (is_file($gpgpath) || is_link($gpgpath))) { ?>
                <span>Download: <?= $this->Html->link(__('Server PGP public key'), $this->webroot.'gpg.asc'); ?></span>
            <?php } else { ?>
                <span><?= __('Could not locate the PGP public key.'); ?></span>
            <?php }
            if (Configure::read('SMIME.enabled')):
                $smimepath = ROOT.DS.APP_DIR.DS.WEBROOT_DIR.DS.'public_certificate.pem';
                if (file_exists($smimepath) && (is_file($smimepath) || is_link($gpgpath))) { ?>
                    <span>Download: <?= $this->Html->link(__('Server S/MIME certificate'), $this->webroot.'public_certificate.pem'); ?></span>
                <?php } else { ?>
                    <span><?= __('Could not locate S/MIME certificate.'); ?></span>
                <?php }
            endif; ?>
        </div>

        <!-- Center section: Footer text -->
        <div class="col text-center">
            <span>
                <?= h(Configure::read('MISP.footermidleft')); ?> 
                Powered by <a href="https://github.com/MISP/MISP" rel="noopener" class="text-primary">MISP <?= isset($me['id']) ? h($mispVersionFull) : '' ?></a> 
                <?= h(Configure::read('MISP.footermidright')); ?> - <?= $this->Time->time(time()) ?>
            </span>
        </div>

        <!-- Right section: Logo -->
        <div class="col text-end">
            <?php if (Configure::read('MISP.footer_logo')): ?>
                <img src="<?= $this->Image->base64(APP . 'files/img/custom/' . Configure::read('MISP.footer_logo')) ?>" 
                    alt="<?= __('Footer logo') ?>" 
                    class="img-fluid"
                    style="max-height:30px;" 
                    onerror="this.style.display='none';">
            <?php endif; ?>
        </div>
    </footer>
</div>


<script>
document.getElementById('triangle').addEventListener('click', function() {
    document.querySelector('.expansion').classList.toggle('footer-expanded');
});
</script>