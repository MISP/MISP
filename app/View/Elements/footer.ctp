<div class="footer">
	<div class="navbar navbar-inverse" style="padding-left:20px;">
		<div class="navbar-inner row">
			<div class="pull-left">
				<span style="float:left;color:#999999;padding-top:12px;">Download: <?php echo $this->Html->link('PGP/GPG key', '/gpg.asc');?></span>
			</div>
			<div style="padding-top:12px;position: absolute;width:100%;text-align:center;color: #999999;">
				<span> <?php if (isset($me)) echo Configure::read('CyDefSIG.footerversion'); else echo Configure::read('CyDefSIG.footer')?></span>
			</div>
			<div class="pull-right">
				<?php if (Configure::read('MISP.footer_logo')): ?>
					<span style="color: #999999;padding-right:20px;padding-top:12px;">Powered by: </span>
					<img src="/img/<?php echo Configure::read('MISP.footer_logo')?>.png" style="height:40px" alt="" />
				<?php endif;?>
			</div>
		</div>
	</div>
</div>
