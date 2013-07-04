<?php
	if (Configure::read('debug') == 0) {
		?>
<div class="footer debugOff">
		<?php
	} else {
		?>
<div class="footer debugOn">
		<?php
	}
?>
	<div class="navbar navbar-inverse" style="padding-left:20px;">
		<div class="navbar-inner row">
			<div class="pull-left footerText" style="float:left;position:absolute;padding-top:12px;z-index:2;">
				<span>Download: <?php echo $this->Html->link('PGP/GPG key', '/gpg.asc');?></span>
			</div>
			<div class = "footerText footerCenterText">
				<span> <?php if (isset($me)) echo Configure::read('CyDefSIG.footerversion'); else echo Configure::read('CyDefSIG.footer')?></span>
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
