<div class="users form">
<h2>MISP Terms and Conditions</h2>

<?php
$termsFile = APP ."View/Users/terms";

if (!(file_exists($termsFile))) {
	echo "<p>Please add your terms and conditions in file $termsFile.</p>";
}else {
	$terms = new File($termsFile, false);
	echo $terms->read(true,'r');
	$terms->close();
}
?>

<?php
if (!$termsaccepted) {
	echo $this->Form->create('User');
	echo $this->Form->hidden('termsaccepted', array('default' => '1'));
	echo $this->Form->end(__('Accept Terms', true));
}
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'terms'));
?>