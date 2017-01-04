<div class="event index">
	<h2>Listing invalid attribute validations</h2>
	<?php
		foreach ($result as $r) {
			?>
			<h3>Validation errors for attribute: <?php echo h($r['id']); ?></h3>
			<?php
				foreach ($r['error'] as $field => $error) {
					echo '<b>[' . h($field) . ']</b>: Value found: ' . h($error['value']) . ' - Error: ' . h($error['error']) . '<br />';
				}
			?>
			<b>[Attribute details]</b>: <?php echo h($r['details']); ?><br/>
	<?php
		}
	?>
</div>
<?php
echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
