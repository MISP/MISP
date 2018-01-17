<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta http-equiv="X-UA-Compatible" content="IE=edge" />
	<?php echo $this->Html->charset(); ?>
	<title>
		<?php echo $title_for_layout, ' - '. h(Configure::read('MISP.title_text') ? Configure::read('MISP.title_text') : 'MISP'); ?>
	</title>
	<?php
		if (!isset($debugMode)) {
			$debugMode == 'debugOff';
		} else {
			$debugMode == 'debugOn';
		}
		echo $this->Html->meta('icon');
		//echo $this->Html->css('roboto');
		echo $this->Html->css('bootstrap');
		echo $this->Html->css('bootstrap-datepicker');
		echo $this->Html->css('bootstrap-timepicker');
		echo $this->Html->css('bootstrap-colorpicker');
		echo $this->Html->css('famfamfam-flags');
		echo $this->Html->css('font-awesome');
		if ($me) {
			echo $this->Html->css('main.css?' . $queryVersion);
		} else {
			echo $this->Html->css('main');
		}
		if (Configure::read('MISP.custom_css')) {
			$css = preg_replace('/\.css$/i', '', Configure::read('MISP.custom_css'));
			echo $this->Html->css($css);
		}
		echo $this->Html->css('print', 'stylesheet', array('media' => 'print'));

		echo $this->fetch('meta');
		echo $this->fetch('css');
		echo $this->fetch('script');

		echo $this->Html->script('jquery'); // Include jQuery library
		echo $this->Html->script('misp-touch'); // touch interface support
	?>

</head>
<body>
	<div id="popover_form" class="ajax_popover_form"></div>
	<div id="screenshot_box" class="screenshot_box"></div>
	<div id="confirmation_box" class="confirmation_box"></div>
	<div id="gray_out" class="gray_out"></div>
		<div id="container">
			<?php echo $this->element('global_menu');
			    $padding_top = 10;
			    if ($debugMode == 'debugOff') $padding_top = 50;
			?>
		<div id="main-view-container" class="container-fluid <?php echo $debugMode; ?>-layout">
			<?php
				$has_flash = false;
			    $flash = array();
			    $flash[] = $this->Session->flash('email');
			    $flash[] = $this->Session->flash();
			    $flash[] = $this->Session->flash('gpg');
			    $flash[] = $this->Session->flash('error');
			    $flash[] = $this->Session->flash('auth');
			    foreach ($flash as $f) {
					if ($f) {
						echo $f;
						$has_flash = true;
						continue;
					}
	            }
			?>
		</div>
		<?php
			$topGap = 50;
			if (Configure::read('debug') > 1) {
				$topGap = 10;
			} else {
				if ($has_flash) $topGap += 50;
			}
		?>
		<div style="padding-top:<?php echo $topGap; ?>px !important;">
			<?php echo $this->fetch('content'); ?>
		</div>
	</div>
	<?php
	echo $this->element('footer');
	echo $this->element('sql_dump');
	echo $this->Html->script('bootstrap');
	echo $this->Html->script('bootstrap-timepicker');
	echo $this->Html->script('bootstrap-datepicker');
	echo $this->Html->script('bootstrap-colorpicker');
	if ($me) {
		echo $this->Html->script('misp.js?' . $queryVersion);
	}
	?>
	<div id = "ajax_success_container" class="ajax_container">
		<div id="ajax_success" class="ajax_result ajax_success"></div>
	</div>
	<div id = "ajax_fail_container" class="ajax_container">
		<div id="ajax_fail" class="ajax_result ajax_fail"></div>
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
