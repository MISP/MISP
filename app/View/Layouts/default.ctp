<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta http-equiv="X-UA-Compatible" content="IE=edge" />
	<?php echo $this->Html->charset(); ?>
	<title>
		<?php echo $title_for_layout, ' - ', Configure::read('MISP.name')?>
	</title>
	<?php
		echo $this->Html->meta('icon');
// 		echo $this->Html->css('cake.generic');
		echo $this->Html->css('roboto');
		echo $this->Html->css('bootstrap'); // see http://twitter.github.io/bootstrap/base-css.html
		echo $this->Html->css('datepicker');
		echo $this->Html->css('bootstrap-timepicker');
		echo $this->Html->css('bootstrap-colorpicker.min');
		echo $this->Html->css('main');
		echo $this->Html->css('print', 'stylesheet', array('media' => 'print'));

		// FIXME chri: re-add print stylesheet
		//echo $this->Html->css(array('print'), 'stylesheet', array('media' => 'print'));

		echo $this->fetch('meta');
		echo $this->fetch('css');
		echo $this->fetch('script');

		echo $this->Html->script('jquery-2.1.0.min'); // Include jQuery library
	?>

<!--?php echo $scripts_for_layout; ?-->
</head>
<body>
	<div id="container">
		<?php echo $this->element('global_menu');
			if ($debugMode == 'debugOff') {
				?>
					<div class="container-fluid debugOff" style="padding-top:50px;width:98%;">
				<?php
			} else {
				?>
					<div class="container-fluid debugOn" style="padding-top:10px;width:98%;">
				<?php
			}
			echo $this->Session->flash('auth');
			echo $this->Session->flash('error');
    		echo $this->Session->flash('gpg');
			echo $this->Session->flash();
			echo $this->Session->flash('email'); ?>
		</div>
		<div
			<?php
				if (Configure::read('debug') == 0) echo 'class="topGap"';
			?>
		>	
			<?php echo $this->fetch('content'); ?>
		</div>
	<?php
	echo $this->element('footer');
	echo $this->element('sql_dump');
	echo $this->Html->script('bootstrap');
	// echo $this->Html->script('bootstrap.min');
	echo $this->Html->script('bootstrap-timepicker');
	echo $this->Html->script('bootstrap-datepicker');
	echo $this->Html->script('bootstrap-colorpicker.min');
	echo $this->Html->script('main');
	?>
	</div>
	<div class="loading">
		<div class="spinner"></div>
		<div class="loadingText">Loading</div>
	</div>
	<?php
		if ($debugMode == 'debugOff'):
	?>
	<script type="text/javascript">
		$(window).scroll(function(e) {
			$('.actions').css('left',-$(window).scrollLeft());
		});
	</script>
	<?php 
		endif;
	?>
</body>
</html>
