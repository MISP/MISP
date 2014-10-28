<div class="users form">
<h2>MISP Terms and Conditions</h2>
<?php
	$embedableExtensions = array('pdf');
	if (!Configure::read('MISP.terms_file')) {
		$termsFile = APP ."View/Users/terms";
	} else {
		$termsFile = APP . 'files' . DS . 'terms' . DS . Configure::read('MISP.terms_file');
	}
	if (!(file_exists($termsFile))) {
		echo "<p>Terms and Conditions file not found.</p>";
	} else {
		if (!Configure::read('MISP.terms_download')) {
			$terms = new File($termsFile, false);
			echo $terms->read(true,'r');
			$terms->close();
		} else {
			?>
				<a href="/users/downloadTerms" class="btn btn-primary">Download Terms and Conditions</a>
			<?php 
		}
	}
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'terms'));
?>