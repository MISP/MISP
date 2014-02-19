<?php
echo "<?php\n";
echo "App::uses('{$plugin}AppController', '{$pluginPath}Controller');\n";
?>
/**
 *
<?php
if (!$isScaffold) {
	$defaultModel = Inflector::singularize($controllerName);
	echo " * @property {$defaultModel} \${$defaultModel}\n";
	if (!empty($components)) {
		foreach ($components as $component) {
			echo " * @property {$component}Component \${$component}\n";
		}
	}
}
?>
 */
class <?php echo $controllerName; ?>Controller extends <?php echo $plugin; ?>AppController {

<?php if ($isScaffold): ?>
	public $scaffold;
<?php else:

	if (count($helpers)):
		echo "/**\n * Helpers\n *\n * @var array\n */\n";
		echo "\tpublic \$helpers = array(";
		for ($i = 0, $len = count($helpers); $i < $len; $i++):
			if ($i != $len - 1):
				echo "'" . Inflector::camelize($helpers[$i]) . "', ";
			else:
				echo "'" . Inflector::camelize($helpers[$i]) . "'";
			endif;
		endfor;
		echo ");\n\n";
	endif;

	if (count($components)):
		echo "/**\n * Components\n *\n * @var array\n */\n";
		echo "\tpublic \$components = array(";
		for ($i = 0, $len = count($components); $i < $len; $i++):
			if ($i != $len - 1):
				echo "'" . Inflector::camelize($components[$i]) . "', ";
			else:
				echo "'" . Inflector::camelize($components[$i]) . "'";
			endif;
		endfor;
		echo ");\n\n";
	endif;

	echo trim($actions);

endif; ?>
}
