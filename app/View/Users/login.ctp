<div style="width:100%;">
	<?php
		echo $this->Session->flash('auth');
	?>
<table style="width:1200px;margin-left:auto;margin-right:auto;">
	<tr>
	<td style="text-align:right;width:250px;padding-right:50px">
		<?php if (Configure::read('MISP.welcome_logo')) echo $this->Html->image('custom/' . h(Configure::read('MISP.welcome_logo')), array('alt' => 'Logo', 'onerror' => "this.style.display='none';")); ?>
	</td>
	<td style="width:450px">
		<span style="font-size:18px;">
			<?php
				if (Configure::read('MISP.welcome_text_top')) {
					echo h(Configure::read('MISP.welcome_text_top'));
				}
			?>
		</span><br /><br />
		<div style="width:100%;">
		<?php if (Configure::read('MISP.main_logo') && file_exists(APP . '/webroot/img/custom/' . Configure::read('MISP.main_logo'))): ?>
			<img src="<?php echo $baseurl?>/img/custom/<?php echo h(Configure::read('MISP.main_logo'));?>" style=" display:block; margin-left: auto; margin-right: auto;" />
		<?php else: ?>
			<img src="/img/misp-logo.png" style="display:block; margin-left: auto; margin-right: auto;"/>
		<?php endif;?>
		</div>
		<?php
			if (true == Configure::read('MISP.welcome_text_bottom')):
		?>
				<div style="text-align:right;font-size:18px;">
				<?php
					echo h(Configure::read('MISP.welcome_text_bottom'));
				?>
				</div>
		<?php
			endif;
			echo $this->Form->create('User');
		?>
		<legend style="width:450px;">Login</legend>
		<?php
			echo $this->Form->input('email', array('autocomplete' => 'off'));
			echo $this->Form->input('password', array('autocomplete' => 'off'));
		?>
			<div class="clear"></div>
		<?php
			echo $this->Form->button('Login', array('class' => 'btn btn-primary'));
			echo $this->Form->end();
		?>
	</td>
	<td style="width:250px;padding-left:50px">
		<?php if (Configure::read('MISP.welcome_logo2')) echo $this->Html->image('custom/' . h(Configure::read('MISP.welcome_logo2')), array('alt' => 'Logo2', 'onerror' => "this.style.display='none';")); ?>
	</td>
	</tr>
	</table>
</div>
