<div class="event index">
	<h2>Listing invalid event validations</h2>
	Events analysed: <?php echo $count; ?><br />
	<?php
		foreach ($result as $r) {
			?>
			<h3>Validation errors for event: <?php echo h($r['id']); ?></h3>
			<?php print_r($r['error']); ?><br />
			Attribute details:<br />
				<?php print_r(h($r['details'])); ?>
			<br/>
	<?php
		}
	?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
