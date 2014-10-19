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
				<?php }
					$smimepath_s = ROOT.DS.APP_DIR.DS.WEBROOT_DIR.DS.'public_certificate.pem';
					if(file_exists($smimepath_s) && is_file($smimepath_s)){ ?>
						<span>Download: <?php echo $this->Html->link('Certificate (Encipherment)', $this->webroot.'public_certificate.pem');?></span>
				<?php }else{ ?>
          <span>Could not locate the Certificate (Encipherment).</span>
        <?php } ?>				
			</div>
			<div class = "footerText footerCenterText">
				<?php 
					$footerText = Configure::read('MISP.footerpart1') . ' ' . Configure::read('MISP.footerpart2');
					if (isset($me['id'])) $footerText = Configure::read('MISP.footerpart1') . ' version ' . $mispVersion . ' ' . Configure::read('MISP.footerpart2');
				?>
				<span> <?php echo $footerText; ?> </span>
			</div>
			<div class="pull-right" style="position:relative;padding-top:9px;z-index:2;">
				<?php if (Configure::read('MISP.footer_logo')): ?>
					<img src="/img/<?php echo Configure::read('MISP.footer_logo');?>.png" style="height:24px;" />
				<?php endif;?>
			</div>
		</div>
	</div>
</div>
