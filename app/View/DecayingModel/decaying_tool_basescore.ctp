<div id="basescore_configurator" class="row">
    <div class="span8" class="taxonomyTableContainer">
        <input id="table_taxonomy_search" class="input" style="width: 250px; margin: 0px;" type="text" placeholder="<?php echo __('Search Taxonomy'); ?>"></input>
        <i class="fa fa-times useCursorPointer" title="<?php echo __('Clear search field'); ?>" onclick="$('#table_taxonomy_search').val('').trigger('input');"></i>
        <span style="float: right; margin-top: 6px;" class="badge badge-info"><b><?php echo h($taxonomies_not_having_numerical_value); ?></b><?php echo __(' not having numerical value'); ?></span>
        <div class="input-prepend" style="margin: 4px;">
            <span class="add-on"><?php echo __('Default basescore') ?></span>
            <input id="base_score_default_value" type="number" min=0 max=100 class="input-mini" value="0" placeholder="0"></input>
        </div>
        <table id="tableTaxonomy" class="table table-striped table-bordered table-condensed">
            <thead>
                <tr>
                    <th><?php echo __('Taxonomies') ?></th>
                    <th><?php echo __('Weight') ?></th>
                </tr>
            </thead>
            <tbody id="body_taxonomies">
                <?php foreach ($taxonomies as $name => $taxonomy): ?>
                    <?php if (count($taxonomy['TaxonomyPredicate']) > 0): ?>
                        <tr class="bold useCursorPointer" data-namespace="<?php echo h($name); ?>" onclick="collapseNamespace(this);">
                            <td colspan=2 style="background-color: #999; color: white; user-select: none;">
                                <?php echo h($name); ?>
                                <i class="caretIconExpand fas fa-caret-down"></i>
                            </td>
                        </tr>
                    <?php endif; ?>
                    <?php foreach ($taxonomy['TaxonomyPredicate'] as $p => $predicate): ?>
                        <?php if (!isset($predicate['numerical_predicate']) || !$predicate['numerical_predicate']): ?>
                            <tr data-namespace="<?php echo h($name); ?>">
                                <td>
                                    <div class="btn-group">
                                        <a class="btn dropdown-toggle" data-toggle="dropdown" href="#">
                                            <?php echo h($predicate['value']) ?>
                                            <span class="caret"></span>
                                        </a>
                                        <ul class="dropdown-menu">
                                            <?php foreach ($predicate['TaxonomyEntry'] as $e => $entry): ?>
                                                <li>
                                                    <a style="position: relative; padding: 3px 5px;">
                                                        <span class="tagComplete"
                                                        style="margin-right: 35px;background-color: <?php echo h($entry['Tag']['colour']); ?>;color:<?php echo h($this->TextColour->getTextColour($entry['Tag']['colour']));?>"
                                                        title="<?php echo sprintf('%s: %s', h($entry['expanded']), h($entry['description'])) ?>"><?php echo h($entry['Tag']['name']); ?>
                                                        </span>
                                                        <span class="label label-inverse numerical-value-label"><?php echo h($entry['numerical_value']) ?></span>
                                                    </a>
                                                </li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                </td>
                                <td>
                                    <input id="slider_<?php echo h($name) ?>" data-taxonomyname="<?php echo sprintf('%s:%s', h($name), h($predicate['value'])); ?>" type="range" min=0 max=100 step=1 value="<?php echo isset($taxonomy['value']) ? h($taxonomy['value']) : 0 ?>" onchange="sliderChanged(this);" oninput="sliderChanged(this);"></input>
                                    <input type="number" min=0 max=100 step=1 value="<?php echo isset($taxonomy['value']) ? h($taxonomy['value']) : 0 ?>" class="taxonomySlider" data-taxonomyname="<?php echo sprintf('%s:%s', h($name), h($predicate['value'])); ?>" onchange="inputChanged(this);" oninput="inputChanged(this);"></input>
                                </td>
                            </tr>
                        <?php else: // numerical_value on predicate ?>
                            <tr data-namespace="<?php echo h($name); ?>">
                                <td>
                                    <div class="btn-group">
                                        <a class="btn dropdown-toggle" data-toggle="dropdown" href="#">
                                            <?php echo h($name) ?>
                                            <span class="caret"></span>
                                        </a>
                                        <ul class="dropdown-menu">
                                            <?php foreach ($taxonomies[$name]['TaxonomyPredicate'] as $p => $predicate): ?>
                                                <li>
                                                    <a style="position: relative; padding: 3px 5px;">
                                                        <span class="tagComplete"
                                                        style="margin-right: 35px;background-color: <?php echo h($predicate['Tag']['colour']); ?>;color:<?php echo h($this->TextColour->getTextColour($predicate['Tag']['colour']));?>"
                                                        title="<?php echo sprintf('%s: %s', h($predicate['expanded']), h($predicate['description'])) ?>"><?php echo h($predicate['Tag']['name']); ?>
                                                        </span>
                                                        <span class="label label-inverse numerical-value-label"><?php echo h($predicate['numerical_value']) ?></span>
                                                    </a>
                                                </li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                </td>
                                <td>
                                    <input id="slider_<?php echo h($name) ?>" data-taxonomyname="<?php echo h($name); ?>" type="range" min=0 max=100 step=1 value="<?php echo isset($taxonomy['value']) ? h($taxonomy['value']) : 0 ?>" onchange="sliderChanged(this);" oninput="sliderChanged(this);"></input>
                                    <input type="number" min=0 max=100 step=1 value="<?php echo isset($taxonomy['value']) ? h($taxonomy['value']) : 0 ?>" class="taxonomySlider" data-taxonomyname="<?php echo h($name); ?>" onchange="inputChanged(this);" oninput="inputChanged(this);"></input>
                                </td>
                            </tr>
                            <?php break; ?>
                        <?php endif; ?>
                    <?php endforeach; ?>
                <?php endforeach; ?>
                <?php if (count($excluded_taxonomies) > 1): ?>
                    <tr class="bold useCursorPointer" data-namespace="excluded-taxonomy" onclick="collapseNamespace(this);">
                        <td colspan=2 style="background-color: #999; color: white; user-select: none;">
                            <?php echo __('Excluded'); ?>
                            <i class="caretIconExpand fas fa-caret-up"></i>
                        </td>
                    </tr>
                <?php endif; ?>
                <?php foreach ($excluded_taxonomies as $namespace => $taxonomy): // excluded taxonomies ?>
                    <tr data-namespace="excluded-taxonomy" style="display: none;">
                        <td>
                            <button class="btn" disabled><?php echo h($namespace) ?></button>
                        </td>
                        <td style="vertical-align: middle;"><span class='label label-info'><?php echo h($taxonomy['reason']); ?></span></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <div class="span8">
        <div style="margin-bottom: 5px;">
            <div id="treemapGraphTax"></div>
        </div>
        <div class="org-source-confidence-placeholder">
            <?php echo __('Placeholder for `Organisation source confidence`') ?>
        </div>
        <div>
            <h3><?php echo __('Example') ?><it class="fa fa-sync useCursorPointer" style="margin-left: 5px; font-size: small;" onclick="refreshExamples()"></it></h3>
            <table id="tableExamples" class="table table-striped table-bordered table-condensed">
                <thead>
                    <tr>
                        <th>Attribute</th>
                        <th>Tags</th>
                        <th style="min-width: 60px;">Base score</th>
                    </tr>
                </thead>
                <tbody>
                    <tr onclick="genHelpBaseScoreComputation(event, 0)">
                        <td>
                            Tag your attribute
                        </td>
                        <td id="basescore-example-tag-0">
                            <div style="width:100%;display:inline-block;" data-original-title="" title="">
                                <div id="basescore-example-customtag-container" style="float: left;display: flex;flex-flow: wrap;" data-original-title="" title="">
                                    <button id="basescore-example-score-addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px; margin-right: 3px;" title="Add tag" onclick="event.stopPropagation(); addTagWithValue(this);">+</button>
                                </div>
                            </div>
                        </td>
                        <td id="basescore-example-score-0" class="basescore-example-score">
                        </td>
                    </tr>
                    <tr onclick="genHelpBaseScoreComputation(event, 1)">
                        <td>Attribute 1</td>
                        <td id="basescore-example-tag-1"><?php echo __('Pick a Taxonomy'); ?></td>
                        <td id="basescore-example-score-1" class="basescore-example-score"></td>
                    </tr>
                    <tr onclick="genHelpBaseScoreComputation(event, 2)">
                        <td>Attribute 2</td>
                        <td id="basescore-example-tag-2"><?php echo __('Pick a Taxonomy'); ?></td>
                        <td id="basescore-example-score-2" class="basescore-example-score"></td>
                    </tr>
                    <tr onclick="genHelpBaseScoreComputation(event, 3)">
                        <td>Attribute 3</td>
                        <td id="basescore-example-tag-3"><?php echo __('Pick a Taxonomy'); ?></td>
                        <td id="basescore-example-score-3" class="basescore-example-score"></td>
                    </tr>
                </tbody>
            </table>

            <h3><?php echo __('Computation steps') ?></h3>
            <?php echo $this->element('DecayingModels/View/basescore_computation_steps'); ?>
        </div>
        <span class="btn btn-primary" style="margin-top: 5px;" onclick="applyBaseScoreConfig();"><i class="fas fa-wrench"> <?php echo __('Apply base score'); ?></i></span>
    </div>
</div>

<?php
    echo $this->element('genericElements/assetLoader', array(
        'css' => array('treemap'),
        'js' => array('decayingToolBasescore')
    ));
?>

<script>
    var taxonomies_with_num_value = <?php echo json_encode($taxonomies); ?>;
    function collapseNamespace(clicked) {
        var $tr = $(clicked)
        var $icon = $tr.find('i.caretIconExpand');
        var namespace = $tr.data('namespace');
        $tr.parent().find('[data-namespace="' + namespace + '"]').not($tr).toggle();
        $icon.toggleClass('fa-caret-down').toggleClass('fa-caret-up');
    }
</script>
