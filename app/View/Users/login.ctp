<div style="width:100%;">
	<?php
		echo $this->Session->flash('auth');
	?>
<table style="width:1200px;margin-left:auto;margin-right:auto;">
	<tr>
	<td style="text-align:right;width:250px;padding-right:50px">
	<?php 
		if (true == Configure::read('MISP.welcome_logo')) {
	?>
		<?php if (Configure::read('MISP.welcome_logo')): ?>
			<img src="
					<?php
					echo Configure::read('MISP.url') . '/img/';
					echo Configure::read('MISP.welcome_logo');
					?>
			.png" alt="" />
		<?php endif; ?>
		</td>
	<?php
		}
	?>
	<td style="width:600px">
		<span style="font-size:18px;"><?php
			if (true == Configure::read('MISP.welcome_text_top')) {
				echo Configure::read('MISP.welcome_text_top');
			}?></span><br /><br />
		<div class="nav" style="font-weight:bold; font-size:30px;text-align:center;">
			<span class="logoBlue">M</span><span style="color: #000000;">alware</span>
			<span class="logoBlue">I</span><span style="color: #000000;">nformation </span>
			<span class="logoBlue">S</span><span style="color: #000000;">haring</span>
			<span class="logoBlue">P</span><span style="color: #000000;">latform</span>
		</div>
		<?php
			if (true == Configure::read('MISP.welcome_text_bottom')) {
		?>
		<div style="text-align:right;font-size:18px;">
		<?php
				echo Configure::read('MISP.welcome_text_bottom');
		?>
		</div>
		<div>
		<?php
			}
			echo $this->Form->create('User', array('action' => 'login'));
			echo $this->Form->inputs(array(
				'legend' => __('Login', true),
				'email' => array('autocomplete' => 'off'),
				'password' => array('autocomplete' => 'off')
			));
			echo $this->Form->button('Login', array('class' => 'btn btn-primary'));
			echo $this->Form->end();
		?>
		</div>
	</td>
	<td style="width:250px;padding-left:50px">
		<?php if (Configure::read('MISP.welcome_logo2')): ?>
			<img src="
				<?php
				echo Configure::read('MISP.url') . '/img/';
				echo Configure::read('MISP.welcome_logo2');
				?>
		.png" alt="" />
		<?php endif; ?>
	</td>
	</tr>
	</table>
</div>
</div>