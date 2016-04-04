<div class="footer <?php echo $debugMode;?>">
	<div class="navbar navbar-inverse">
		<div class="glass"></div>
		<div class="navbar-inner" style="border-radius: 10px;">
			<div class="pull-left footerText" style="float:left;position:absolute;padding-top:12px;z-index:2;">
				<?php
				$gpgpath = ROOT.DS.APP_DIR.DS.WEBROOT_DIR.DS.'gpg.asc';
				if(file_exists($gpgpath) && is_file($gpgpath)){ ?>
					<span>Download: <?php echo $this->Html->link('PGP/GPG key', $this->webroot.'gpg.asc');?></span>
				<?php }else{ ?>
					<span>Could not locate the PGP/GPG public key.</span>
				<?php } ?>
			</div>
			<div class = "footerText footerCenterText">
				<?php 
					$footerText = Configure::read('MISP.footerpart1') . ' ' . Configure::read('MISP.footerpart2');
					if (isset($me['id'])) $footerText = Configure::read('MISP.footerpart1') . ' version ' . $mispVersionFull . ' ' . Configure::read('MISP.footerpart2');
				?>
				<span> <?php echo h($footerText); ?> </span>
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
