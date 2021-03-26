<div class="footer <?php echo $debugMode;?>">
    <div id="shortcutsListContainer" class="<?php echo $debugMode == 'debugOn' ? 'hidden': ''; ?>">
        <div id="triangle"></div>
        <div id="shortcutsList">
            <span> <?php echo __('Keyboard shortcuts for this page'); ?>:</span><br>
            <div id="shortcuts"><?php echo __('none'); ?></div>
        </div>
    </div>
    <div id="footerContainer" class="navbar navbar-inverse">
        <div class="navbar-inner">
            <div class="pull-left footerText" style="float:left;position:absolute;padding-top:12px;z-index:2;">
                <?php
                $gpgpath = ROOT.DS.APP_DIR.DS.WEBROOT_DIR.DS.'gpg.asc';
                if (Configure::read("MISP.download_gpg_from_homedir")) { ?>
                    <span>Download: <?= $this->Html->link(__('PGP public key'), array('controller' => 'users', 'action' => 'getGpgPublicKey')) ?></span>
                <?php } else if (file_exists($gpgpath) && (is_file($gpgpath) || is_link($gpgpath))) { ?>
                    <span>Download: <?php echo $this->Html->link(__('PGP public key'), $this->webroot.'gpg.asc');?></span>
                <?php } else { ?>
                    <span><?php echo __('Could not locate the PGP public key.');?></span>
                <?php }
                if (Configure::read('SMIME.enabled')):
                    $smimepath = ROOT.DS.APP_DIR.DS.WEBROOT_DIR.DS.'public_certificate.pem';
                    if (file_exists($smimepath) && (is_file($smimepath) || is_link($gpgpath))) { ?>
                        <span>Download: <?php echo $this->Html->link(__('S/MIME certificate'), $this->webroot.'public_certificate.pem');?></span>
                    <?php } else { ?>
                        <span><?php echo __('Could not locate S/MIME certificate.');?></span>
                    <?php }
                endif;
                ?>
            </div>
            <div class="footerText footerCenterText">
                <span><?= h(Configure::read('MISP.footermidleft')); ?> Powered by <a href="https://github.com/MISP/MISP" rel="noopener">MISP <?= isset($me['id']) ? h($mispVersionFull) : '' ?></a> <?= h(Configure::read('MISP.footermidright')); ?> - <?= $this->Time->time(time()) ?></span>
            </div>
            <div class="pull-right" style="position:relative;padding-top:9px;z-index:2;">
                <?php
                    if (Configure::read('MISP.footer_logo')) {
                        echo $this->Html->image('custom/' . h(Configure::read('MISP.footer_logo')), array('alt' => 'Footer Logo', 'onerror' => "this.style.display='none';", 'style' => 'height:24px'));
                    }
                ?>
            </div>
        </div>
    </div>
</div>
