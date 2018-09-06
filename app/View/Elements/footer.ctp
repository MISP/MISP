<div class="footer <?php echo $debugMode;?>">
    <div id="shortcutsListContainer" class="<?php echo $debugMode ? 'hidden': ''; ?>">
        <div id="triangle"></div>
        <div id="shortcutsList">
            <span> <?php echo __('Keyboard shortcuts for this page'); ?>:</span><br />
            <div id="shortcuts"><?php echo __('none'); ?></div>
        </div>
    </div>
    <div id="footerContainer" class="navbar navbar-inverse">
        <div class="navbar-inner">
            <div class="pull-left footerText" style="float:left;position:absolute;padding-top:12px;z-index:2;">
                <?php
                $gpgpath = ROOT.DS.APP_DIR.DS.WEBROOT_DIR.DS.'gpg.asc';
                if (file_exists($gpgpath) && (is_file($gpgpath) || is_link($gpgpath))){ ?>
                    <span>Download: <?php echo $this->Html->link(__('GnuPG key'), $this->webroot.'gpg.asc');?></span>
                <?php } else { ?>
                    <span><?php echo __('Could not locate the GnuPG public key.');?></span>
                <?php }
                if (Configure::read('SMIME.enabled')):
                    $smimepath = ROOT.DS.APP_DIR.DS.WEBROOT_DIR.DS.'public_certificate.pem';
                    if (file_exists($smimepath) && (is_file($smimepath) || is_link($gpgpath))){ ?>
                        <span>Download: <?php echo $this->Html->link('SMIME certificate', $this->webroot.'public_certificate.pem');?></span>
                    <?php } else { ?>
                        <span><?php echo __('Could not locate SMIME certificate.');?></span>
                    <?php }
                endif;
                ?>
            </div>
            <div class = "footerText footerCenterText">
                <span><?php echo h(Configure::read('MISP.footermidleft')); ?> Powered by <a href="https://github.com/MISP/MISP">MISP <?php if (isset($me['id'])) echo h($mispVersionFull);?></a> <?php echo h(Configure::read('MISP.footermidright')); ?> - <?php echo date("Y-m-d H:i:s"); ?></span>
            </div>
            <div class="pull-right" style="position:relative;padding-top:9px;z-index:2;">
                <?php
                    if (Configure::read('MISP.footer_logo')) {
                        if (Configure::read('MISP.footer_logo')) echo $this->Html->image('custom/' . h(Configure::read('MISP.footer_logo')), array('alt' => 'Footer Logo', 'onerror' => "this.style.display='none';", 'style' => 'height:24px'));
                    }
                ?>
            </div>
        </div>
    </div>
</div>
