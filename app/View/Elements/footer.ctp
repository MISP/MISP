<div class="footer <?php echo $debugMode;?>">
	<div class="navbar navbar-inverse">
			<div class="pull-left" style="float:left;position:absolute;padding-top:12px;z-index:2;">
				<?php
				$gpgpath = ROOT.DS.APP_DIR.DS.WEBROOT_DIR.DS.'gpg.asc';
				if(file_exists($gpgpath) && is_file($gpgpath)){ ?>
					<span class="text-muted">Download: <?php echo $this->Html->link('PGP/GPG key', $this->webroot.'gpg.asc');?></span>
				<?php }else{ ?>
					<span class="text-muted">Could not locate the PGP/GPG public key.</span>
				<?php } ?>
			</div>
			<div class="footerCenterText">
				<span class="text-muted"><?php echo h(Configure::read('MISP.footermidleft')); ?> Powered by <a href="https://github.com/MISP/MISP">MISP <?php if (isset($me['id'])) echo h($mispVersionFull);?></a> <?php echo h(Configure::read('MISP.footermidright')); ?></span>
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
