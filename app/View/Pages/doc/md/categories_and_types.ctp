### Attribute Categories vs Types<br /><br />

<?php
	$catDefs = array_chunk($categoryDefinitions, 6, true);
	foreach ($catDefs as $cD):
?>

|Category|<?php foreach ($cD as $cat => $catDef) echo ' ' . $cat . ' |'; ?><br />
<?php
		echo '| --- |';
		foreach ($cD as $cat) echo ':---:|';
?><br />
<?php
		foreach ($typeDefinitions as $type => $def) {
			echo '|' . str_replace('|', '&amp;#124;', $type) . '|';
			foreach ($cD as $cat => $catDef) echo (in_array($type, $catDef['types'])? ' X |' : ' |');
			echo '<br />';
		}
		echo '<br />';
	endforeach;
?>

### Categories<br /><br />

<?php foreach ($categoryDefinitions as $cat => $def) {
	echo '*&nbsp;&nbsp;&nbsp;**' . $cat . '**: ';
	if (isset($def['formdesc'])) echo h($def['formdesc']);
	else echo h($def['desc']);
	echo '<br />';
}?>

<br />
### Types<br /><br />

<?php foreach ($typeDefinitions as $type => $def) {
	echo '*&nbsp;&nbsp;&nbsp;**' . $type . '**: ';
	if (isset($def['formdesc'])) echo h($def['formdesc']);
	else echo h($def['desc']);
	echo '<br />';
}?>
