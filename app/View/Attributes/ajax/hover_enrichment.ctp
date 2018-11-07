<?php
$results = array(
	(int) 0 => array(
		'cve' => 'The Graphics Device Interface (GDI) in Microsoft Windows Vista SP2; \n\n\n\nWindows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607 allows local users to gain privileges via a crafted application, aka "Windows GDI Elevation of Privilege Vulnerability." This vulnerability is different from those described in CVE-2017-0005, CVE-2017-0025, and CVE-2017-0047.'
	)
);
    foreach ($results as &$r):
        foreach ($r as $k => &$v):
			echo sprintf('<span class="bold blue">%s</span>: <br />', Inflector::humanize(h($k)));
			if (is_array($v)) {
				foreach ($v as $key => $value) {
					if (!is_numeric($key)) {
						echo '<div class="blue" style="margin-left:10px;">' . h($key) . ':</div>';
					}
					echo '<div class="red" style="margin-left:20px;">' . str_replace('\n', '<br />', h($value)) . '</div>';
				}
			} else {
				echo '<div class="red" style="margin-left:20px;">' . str_replace('\n', '<br />', h($v)) . '</div>';
			}
        endforeach;
    endforeach;
?>
