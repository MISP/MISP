<div style="width:100%;">
<div class="row" style="margin: 0 auto;display:table;">
	<?php
		echo $this->Session->flash('auth');
		if (true == Configure::read('MISP.welcome_logo')) {
	?>
		<div class="span4">
		<img src="
				<?php
				echo Configure::read('CyDefSig.url') . '/img/';
				echo Configure::read('MISP.welcome_logo');
				?>
		.png" alt="" />
		</div>
	<?php
		}
	?>
	<div class="span8">
		<span style="font-size:18px;"><?php
			if (true == Configure::read('MISP.welcome_text_top')) {
				echo Configure::read('MISP.welcome_text_top');
			}?></span><br /><br />
		<div class="nav" style="font-weight:bold; font-size:30px;text-align:center;">
			<span style="color: #0088cc;">M</span><span style="color: #000000;">alware</span>
			<span style="color: #0088cc;">I</span><span style="color: #000000;">nformation </span>
			<span style="color: #0088cc;">S</span><span style="color: #000000;">haring</span>
			<span style="color: #0088cc;">P</span><span style="color: #000000;">latform</span>
		</div>
		<?php
			if (true == Configure::read('MISP.welcome_text_bottom')) {
		?>
		<div style="text-align:right;font-size:18px;">
		<?php
				echo Configure::read('MISP.welcome_text_bottom');
		?>
		</div>
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
</div>
</div>