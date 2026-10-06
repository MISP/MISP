<?php
/**
 * The content of one server settings destination: what the navigation swaps
 * into the page. Its root carries the destination and the per-destination
 * error counters, from which server-settings.js refreshes the navigation
 * badges on every swap.
 *
 * View variables: destination, definition, destinations, sectionsByDestination,
 * counters, healthVerdicts (+ the kind-specific ones the controller sets).
 */

$sections = isset($sectionsByDestination[$destination]) ? $sectionsByDestination[$destination] : array();
$badges = array();
foreach ($counters as $id => $byLevel) {
    $badges[$id] = array($byLevel[0], $byLevel[1]);
}
$kind = $definition['kind'];
?>
<div class="ss-page"
     data-ss-page="<?= h($destination) ?>"
     data-ss-title="<?= h($definition['title']) ?>"
     data-ss-counters="<?= h(json_encode($badges)) ?>">
<?php
switch ($kind) {
    case 'overview':
        echo $this->element('healthElementsBS5/settings_overview');
        break;
    case 'settings':
        echo $this->element('healthElementsBS5/settings_page', array(
            'sections' => $sections,
            'tiered' => true,
            'intro' => $destination === 'ai'
                ? $this->element('healthElementsBS5/ai_status', array('status' => $aiModuleStatus))
                : '',
        ));
        if ($destination === 'ai') {
            echo $this->element('healthElementsBS5/ai_dry_run', array('status' => $aiModuleStatus));
        }
        if (!empty($definition['probes'])) {
            echo $this->element('healthElementsBS5/settings_health', array('probes' => $definition['probes']));
        }
        break;
    case 'modules':
        echo $this->element('healthElementsBS5/settings_modules', array('sections' => $sections));
        break;
    case 'integrations':
        echo $this->element('healthElementsBS5/settings_integrations');
        break;
    case 'all':
        echo $this->element('healthElementsBS5/settings_all');
        break;
    case 'health':
        echo $this->element('healthElementsBS5/settings_health', array('probes' => $definition['probes']));
        break;
    case 'maintenance':
        echo $this->element('healthElementsBS5/settings_maintenance');
        break;
    case 'correlations':
        echo $this->element('healthElementsBS5/correlations', array('correlation_metrics' => $correlation_metrics));
        break;
    case 'files':
        echo $this->element('healthElementsBS5/files', array('files' => $files));
        break;
}
?>
</div>
