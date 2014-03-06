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
				<span> <?php if (isset($me)) echo Configure::read('MISP.footerversion'); else echo Configure::read('MISP.footer')?></span>
			</div>
			<div class="pull-right" style="position:relative;">
				<?php if (Configure::read('MISP.footer_logo')): ?>
					<span class = "footerText footerRightText">Powered by: </span>
					<img src="/img/<?php echo Configure::read('MISP.footer_logo')?>.png" style="height:40px;">
				<?php endif;?>
			</div>
		</div>
	</div>
</div>
