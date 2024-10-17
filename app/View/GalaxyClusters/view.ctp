<?php
echo $this->element('genericElements/assetLoader', [
    'js' => ['doT', 'moment.min'],
    'css' => ['analyst-data',],
]);

$extendedFromHtml = '';
if (!empty($cluster['GalaxyCluster']['extended_from'])) {
    $element = $this->element('genericElements/IndexTable/Fields/links', array(
        'url' => $baseurl . '/galaxy_clusters/view/',
        'row' => $cluster,
        'field' => array(
            'data_path' => 'GalaxyCluster.extended_from.GalaxyCluster.id',
            'title' => sprintf(__('%s (version: %s)'), $cluster['GalaxyCluster']['extended_from']['GalaxyCluster']['value'], $cluster['GalaxyCluster']['extends_version'])
        ),
    ));
    $extendedFromHtml = sprintf('<ul><li>%s</li></ul>', $element);
}
if ($newVersionAvailable) {
    $extendedFromHtml .= sprintf('<div class="alert alert-warning">%s</div>', sprintf(__('New version available! <a href="%s">Update cluster to version <b>%s</b></a>'),
        '/galaxy_clusters/updateCluster/' . $cluster['GalaxyCluster']['id'],
        h($cluster['GalaxyCluster']['extended_from']['GalaxyCluster']['version'])
    ));
}

$extendedByHtml = '';
$extendByLinks = array();
foreach ($cluster['GalaxyCluster']['extended_by'] as $extendCluster) {
    $element = $this->element('genericElements/IndexTable/Fields/links', array(
        'url' => '/galaxy_clusters/view/',
        'row' => $extendCluster,
        'field' => array(
            'data_path' => 'GalaxyCluster.id',
            'title' => sprintf(__('%s (parent version: %s)'), $extendCluster['GalaxyCluster']['value'], $extendCluster['GalaxyCluster']['extends_version'])
        ),
    ));
    $extendByLinks[] = sprintf('<li>%s</li>', $element);
}
if (!empty($extendByLinks)) {
    $extendedByHtml = sprintf('<ul>%s</ul>', implode('', $extendByLinks));
}

$description = $this->Markdown->cleanup($cluster['GalaxyCluster']['description']);

$table_data = array();
$table_data[] = array('key' => __('Cluster ID'), 'value' => $cluster['GalaxyCluster']['id']);
$table_data[] = array('key' => __('Name'), 'value' => $cluster['GalaxyCluster']['value']);
$table_data[] = array('key' => __('Parent Galaxy'), 'value' => $cluster['GalaxyCluster']['Galaxy']['name'] ?: $cluster['GalaxyCluster']['Galaxy']['type']);
$table_data[] = array('key' => __('Description'), 'value' => $description, 'value_class' => 'md');
if (!$cluster['GalaxyCluster']['default']) {
    $table_data[] = [
        'key' => __('Published'),
        'boolean' => $cluster['GalaxyCluster']['published'],
    ];
}
$table_data[] = array('key' => __('Default'), 'boolean' => $cluster['GalaxyCluster']['default'], 'class' => 'black');
$table_data[] = array('key' => __('Version'), 'value' => $cluster['GalaxyCluster']['version']);
$table_data[] = [
    'key' => __('UUID'),
    'element' => 'genericElements/SingleViews/Fields/uuidField',
    'element_params' => [
        'data' => $cluster,
        'field' => [
            'path' => 'GalaxyCluster.uuid',
            'object_type' => 'GalaxyCluster',
            'notes_path' => 'GalaxyCluster.Note',
            'opinions_path' => 'GalaxyCluster.Opinion',
            'relationships_path' => 'GalaxyCluster.Relationship',
            'relationshipsInbound_path' => 'GalaxyCluster.RelationshipInbound',
        ]
    ],
];
$table_data[] = array('key' => __('Collection UUID'), 'value' => $cluster['GalaxyCluster']['collection_uuid'], 'value_class' => 'quickSelect');
$table_data[] = array(
    'key' => __('Source'),
    'html' => filter_var($cluster['GalaxyCluster']['source'], FILTER_VALIDATE_URL) ?
        '<a href="' . h($cluster['GalaxyCluster']['source']) . '" rel="noreferrer noopener">' . h($cluster['GalaxyCluster']['source']) :
        h($cluster['GalaxyCluster']['source']),
);
$table_data[] = array('key' => __('Authors'), 'value' => !empty($cluster['GalaxyCluster']['authors']) ? implode(', ', $cluster['GalaxyCluster']['authors']) : __('N/A'));
$table_data[] = array('key' => __('Distribution'), 'element' => 'genericElements/IndexTable/Fields/distribution_levels', 'element_params' => array(
    'row' => $cluster['GalaxyCluster'],
    'field' => array('data_path' => 'distribution')
));
$table_data[] = array(
    'key' => __('Owner Organisation'),
    'html' => $this->OrgImg->getOrgImg(array('name' => $cluster['GalaxyCluster']['Org']['name'], 'id' => $cluster['GalaxyCluster']['Org']['id'], 'size' => 18), true),
);
$table_data[] = array(
    'key' => __('Creator Organisation'),
    'html' => $this->OrgImg->getOrgImg(array('name' => $cluster['GalaxyCluster']['Orgc']['name'], 'id' => $cluster['GalaxyCluster']['Orgc']['id'], 'size' => 18), true),
);
$table_data[] = array('key' => __('Connector tag'), 'value' => $cluster['GalaxyCluster']['tag_name']);
$table_data[] = array('key' => __('Events'), 'html' => isset($cluster['GalaxyCluster']['tag_count']) ?
                    sprintf('<a href="%s">%s</a>',
                        sprintf('%s/events/index/searchtag:%s', $baseurl, h($cluster['GalaxyCluster']['tag_id'])),
                        __n('%s event', '%s events', $cluster['GalaxyCluster']['tag_count'], h($cluster['GalaxyCluster']['tag_count']))
                    ):
                    '<span>0</span>'
                );
if (!empty($extendedFromHtml)) {
    $table_data[] = array('key' => __('Forked From'), 'html' => $extendedFromHtml);
}
if (!empty($extendedByHtml)) {
    $table_data[] = array('key' => __('Forked By'), 'html' => $extendedByHtml);
}
?>
<div class='view'>
    <div class="row-fluid">
        <div class="span8">
            <h2>
                <?= sprintf('%s :: %s', h($cluster['GalaxyCluster']['Galaxy']['name']), h($cluster['GalaxyCluster']['value'])); ?>
            </h2>
            <?php echo $this->element('genericElements/viewMetaTable', array('table_data' => $table_data)); ?>
        </div>
        <div class="span4">
            <div id="analyst_data_thread" class="panel-container"></div>
        </div>
    </div>
    <div class="row-fuild">
        <div id="matrix_container"></div>
    </div>
    <div class="row-fuild">
        <div id="relations_container"></div>
    </div>
    <?php
        if (!empty(Configure::read('Plugin.CyCat_enable'))) {
            $titleHTML = __('CyCat Relationships');
            $titleHTML .= sprintf('<a href="%s" onclick="event.stopPropagation()" title="%s" target="_blank"><img src="%s" style="height: 2.5em"></a>',
                'https://cycat.org/',
                __('CyCAT or the CYbersecurity Resource CATalogue aims at mapping and documenting, in a single formalism and catalogue all the available cybersecurity tools, rules, playbooks, processes and controls.'),
                $baseurl . '/img/CyCat.ico'
            );
            echo $this->element('/genericElements/accordion', [
                'title' => 'CyCat Relationships',
                'titleHTML' => $titleHTML,
                'url' => '/galaxy_clusters/viewCyCatRelations/' . $cluster['GalaxyCluster']['id']
            ]);
        }
    ?>
    <div id="elements_content"></div>
</div>
<?= $this->element('genericElements/assetLoader', [
    'js' => [
        'markdown-it',
        'jquery-ui.min',
    ],
]);
?>
<script>
$(function () {
    $.get("<?= $baseurl ?>/galaxy_elements/index/<?php echo $cluster['GalaxyCluster']['id']; ?>", function(data) {
        $("#elements_content").html(data);
    });
    $.get("<?= $baseurl ?>/galaxy_clusters/viewGalaxyMatrix/<?php echo $cluster['GalaxyCluster']['id']; ?>", function(data) {
        $("#matrix_container").html(data);
    });
    $.get("<?= $baseurl ?>/galaxy_clusters/viewRelations/<?php echo $cluster['GalaxyCluster']['id']; ?>", function(data) {
        $("#relations_container").html(data);
    });
});

md = window.markdownit('default');
md.disable(['image'])
var $md = $('.md');
$md.html(md.render($md.text()));
</script>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'view_cluster')); ?>

<?php

$object_uuid = $cluster['GalaxyCluster']['uuid'];

$notes = $cluster['GalaxyCluster']['Note'] ?? [];
$opinions = $cluster['GalaxyCluster']['Opinion'] ?? [];
$relationships_outbound = $cluster['GalaxyCluster']['Relationship'] ?? [];
$relationships_inbound = $cluster['GalaxyCluster']['RelationshipInbound'] ?? [];
$notesOpinions = array_merge($notes, $opinions);
if(!function_exists("countNotes")) {
    function countNotes($notesOpinions) {
        $notesTotalCount = count($notesOpinions);
        $notesCount = 0;
        $relationsCount = 0;
        foreach ($notesOpinions as $notesOpinion) {
            if ($notesOpinion['note_type'] == 2) { // relationship
                $relationsCount += 1;
            } else {
                $notesCount += 1;
            }
            if (!empty($notesOpinion['Note'])) {
                $nestedCounts = countNotes($notesOpinion['Note']);
                $notesTotalCount += $nestedCounts['total'];
                $notesCount += $nestedCounts['notesOpinions'];
                $relationsCount += $nestedCounts['relations'];
            }
            if (!empty($notesOpinion['Opinion'])) {
                $nestedCounts = countNotes($notesOpinion['Opinion']);
                $notesTotalCount += $nestedCounts['total'];
                $notesCount += $nestedCounts['notesOpinions'];
                $relationsCount += $nestedCounts['relations'];
            }
        }
        return ['total' => $notesTotalCount, 'notesOpinions' => $notesCount, 'relations' => $relationsCount];
    }
}
$counts = countNotes($notesOpinions);
$notesOpinionCount = $counts['notesOpinions'];
$allCounts = [
    'notesOpinions' => $counts['notesOpinions'],
    'relationships_outbound' => count($relationships_outbound),
    'relationships_inbound' => count($relationships_inbound),
];

$options = [
    'container_id' => 'analyst_data_thread',
    'object_type' => 'GalaxyCluster',
    'object_uuid' => $object_uuid,
    'shortDist' => $shortDist,
    'notes' => $notes,
    'opinions' => $opinions,
    'relationships_outbound' => $relationships_outbound,
    'relationships_inbound' => $relationships_inbound,
    'allCounts' => $allCounts,
];

echo $this->element('genericElements/Analyst_data/thread', $options);

?>