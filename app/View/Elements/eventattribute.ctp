<?php
    $urlHere = $this->here;
    $urlHere = explode('/', $urlHere);
    foreach ($urlHere as $k => $v) {
        $urlHere[$k] = urlencode($v);
    }
    $urlHere = implode('/', $urlHere);
    $urlHere = $baseurl . $urlHere;
    $mayModify = ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
    $mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
    $mayChangeCorrelation = !Configure::read('MISP.completely_disable_correlation') && ($isSiteAdmin || ($mayModify && Configure::read('MISP.allow_disabling_correlation')));
    $possibleAction = 'Proposal';
    if ($mayModify) $possibleAction = 'Attribute';
    $all = false;
    if (isset($this->params->params['paging']['Event']['page'])) {
        if ($this->params->params['paging']['Event']['page'] == 0) $all = true;
        $page = $this->params->params['paging']['Event']['page'];
    } else {
        $page = 0;
    }
    $fieldCount = 11;
    if (!empty($event['Sighting'])) {
        foreach ($sightingsData['data'] as $aid => $data) {
            $sightingsData['data'][$aid]['html'] = '';
            foreach ($data as $type => $typeData) {
                $name = (($type != 'expiration') ? Inflector::pluralize($type) : $type);
                $sightingsData['data'][$aid]['html'] .= '<span class=\'blue bold\'>' . ucfirst(h($name)) . '</span><br />';
                foreach ($typeData['orgs'] as $org => $orgData) {
                    $extra = (($org == $me['Organisation']['name']) ? " class=  'bold'" : "");
                    if ($type == 'expiration') {
                        $sightingsData['data'][$aid]['html'] .= '<span ' . $extra . '>' . h($org) . '</span>: <span class=\'orange bold\'>' . date('Y-m-d H:i:s', $orgData['date']) . '</span><br />';
                    } else {
                        $sightingsData['data'][$aid]['html'] .= '<span ' . $extra . '>' . h($org) . '</span>: <span class=\'' . (($type == 'sighting') ? 'green' : 'red') . ' bold\'>' . h($orgData['count']) . ' (' . date('Y-m-d H:i:s', $orgData['date']) . ')</span><br />';
                    }
                }
                $sightingsData['data'][$aid]['html'] .= '<br />';
            }
        }
    }
    $filtered = false;
    if(isset($passedArgsArray)){
        if (count($passedArgsArray) > 0) {
            $filtered = true;
        }
    }
?>
    <div class="pagination">
        <ul>
        <?php
            $params = $this->request->named;
            unset($params['focus']);
            $url = array_merge(array('controller' => 'events', 'action' => 'viewEventAttributes', $event['Event']['id']), $params);
            $this->Paginator->options(array(
                'url' => $url,
                'update' => '#attributes_div',
                'evalScripts' => true,
                'before' => '$(".progress").show()',
                'complete' => '$(".progress").hide()',
            ));
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 60, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        <li class="all <?php if ($all) echo 'disabled'; ?>">
            <?php
                if ($all):
                    echo '<span class="red">' . __('view all') . '</span>';
                else:
                    echo $this->Paginator->link(__('view all'), 'all');
                endif;
            ?>
        </li>
        </ul>
    </div>
<br />
<div id="edit_object_div">
    <?php
        $deleteSelectedUrl = '/attributes/deleteSelected/' . $event['Event']['id'];
        if (empty($event['Event']['publish_timestamp'])) {
            $deleteSelectedUrl .= '/1';
        }
        echo $this->Form->create('Attribute', array('id' => 'delete_selected', 'url' => $deleteSelectedUrl));
        echo $this->Form->input('ids_delete', array(
            'type' => 'text',
            'value' => 'test',
            'style' => 'display:none;',
            'label' => false,
        ));
        echo $this->Form->end();
    ?>
        <?php
        echo $this->Form->create('ShadowAttribute', array('id' => 'accept_selected', 'url' => '/shadow_attributes/acceptSelected/' . $event['Event']['id']));
        echo $this->Form->input('ids_accept', array(
            'type' => 'text',
            'value' => '',
            'style' => 'display:none;',
            'label' => false,
        ));
        echo $this->Form->end();
    ?>
        <?php
        echo $this->Form->create('ShadowAttribute', array('id' => 'discard_selected', 'url' => '/shadow_attributes/discardSelected/' . $event['Event']['id']));
        echo $this->Form->input('ids_discard', array(
            'type' => 'text',
            'value' => '',
            'style' => 'display:none;',
            'label' => false,
        ));
        echo $this->Form->end();
        if (!isset($attributeFilter)) $attributeFilter = 'all';
    ?>
</div>
<div id="attributeList" class="attributeListContainer">
    <?php
        $target = h($event['Event']['id']);
        if ($extended) $target .= '/extended:1';
        echo $this->element('eventattributetoolbar', array(
            'target' => $target,
            'attributeFilter' => $attributeFilter,
            'urlHere' => $urlHere,
            'filtered' =>$filtered,
            'mayModify' => $mayModify,
            'possibleAction' => $possibleAction
        ));
    ?>
    <table class="table table-striped table-condensed">
        <tr>
            <?php
                if ($extended || ($mayModify && !empty($event['objects']))):
                    $fieldCount += 1;
            ?>
                    <th><input class="select_all" type="checkbox" title="<?php echo __('Select all');?>" role="button" tabindex="0" aria-label="<?php echo __('Select all attributes/proposals on current page');?>" onClick="toggleAllAttributeCheckboxes();" /></th>
            <?php
                endif;
            ?>
            <th class="context hidden"><?php echo $this->Paginator->sort('id');?></th>
            <th class="context hidden">UUID</th>
            <th class="context hidden"><?php echo __('First seen') ?> <i class="fas fa-arrow-right"></i> <?php echo __('Last seen') ?></th>
            <th><?php echo $this->Paginator->sort('timestamp', __('Date'), array('direction' => 'desc'));?></th>
            <?php
                if ($extended):
            ?>
                    <th class="event_id"><?php echo $this->Paginator->sort('event_id', __('Event'));?></th>
            <?php
                endif;
            ?>
            <th><?php echo $this->Paginator->sort('Org.name', __('Org')); ?>
            <th><?php echo $this->Paginator->sort('category');?></th>
            <th><?php echo $this->Paginator->sort('type');?></th>
            <th><?php echo $this->Paginator->sort('value');?></th>
            <th><?php echo __('Tags');?></th>
            <?php
                if ($includeRelatedTags) {
                    echo sprintf('<th>%s</th>', __('Related Tags'));
                }
                $fieldCount += 1;
            ?>
            <th><?php echo __('Galaxies');?></th>
            <th><?php echo $this->Paginator->sort('comment');?></th>
            <th><?php echo __('Correlate');?></th>
            <th><?php echo __('Related Events');?></th>
            <th><?php echo __('Feed hits');?></th>
            <th title="<?php echo $attrDescriptions['signature']['desc'];?>"><?php echo $this->Paginator->sort('to_ids', 'IDS');?></th>
            <th title="<?php echo $attrDescriptions['distribution']['desc'];?>"><?php echo $this->Paginator->sort('distribution');?></th>
            <th><?php echo __('Sightings');?></th>
            <th><?php echo __('Activity');?></th>
            <?php
                if ($includeSightingdb) {
                    echo sprintf(
                        '<th>%s</th>',
                        __('SightingDB')
                    );
                    $fieldCount += 1;
                }
                if ($includeDecayScore) {
                    sprintf(
                        '<th class="decayingScoreField" title="%s">%s</th>',
                        __('Decaying Score'),
                        __('Score')
                    );
                    $fieldCount += 1;
                }
            ?>
            <th class="actions"><?php echo __('Actions');?></th>
        </tr>
        <?php
            $elements = array(
                0 => 'attribute',
                1 => 'proposal',
                2 => 'proposal_delete',
                3 => 'object'
            );
            $focusedRow = false;
            foreach ($event['objects'] as $k => $object) {
                $insertBlank = false;
                echo $this->element('/Events/View/row_' . $object['objectType'], array(
                    'object' => $object,
                    'k' => $k,
                    'mayModify' => $mayModify,
                    'mayChangeCorrelation' => $mayChangeCorrelation,
                    'page' => $page,
                    'fieldCount' => $fieldCount,
                    'includeRelatedTags' => !empty($includeRelatedTags) ? 1 : 0,
                    'includeDecayingScore' => !empty($includeDecayingScore) ? 1 : 0,
                    'includeSightingdb' => !empty($includeSightingdb) ? 1 : 0
                ));
                if (!empty($focus) && ($object['objectType'] == 'object' || $object['objectType'] == 'attribute') && $object['uuid'] == $focus) {
                    $focusedRow = $k;
                }
                if (
                    ($object['objectType'] == 'attribute' && !empty($object['ShadowAttribute'])) ||
                    $object['objectType'] == 'object'
                ):
        ?>
                    <tr class="blank_table_row"><td colspan="<?php echo $fieldCount; ?>"></td></tr>
        <?php
                endif;
            }
        ?>
    </table>
</div>
    <?php if ($emptyEvent && (empty($attributeFilter) || $attributeFilter === 'all')): ?>
        <div class="background-red bold">
            <span>
            <?php
                if ($me['org_id'] != $event['Event']['orgc_id']) {
                    echo __('Attribute warning: This event doesn\'t have any attributes visible to you. Either the owner of the event decided to have
a specific distribution scheme per attribute and wanted to still distribute the event alone either for notification or potential contribution with attributes without such restriction. Or the owner forgot to add the
attributes or the appropriate distribution level. If you think there is a mistake or you can contribute attributes based on the event meta-information, feel free to make a proposal');
                } else {
                    echo __('Attribute warning: This event doesn\'t contain any attribute. It\'s strongly advised to populate the event with attributes (indicators, observables or information) to provide a meaningful event');
                }
            ?>
            </span>
        </div>
    <?php endif;?>
    <div class="pagination">
        <ul>
        <?php
            $this->Paginator->options(array(
                'url' => $url,
                'update' => '#attributes_div',
                'evalScripts' => true,
                'before' => '$(".progress").show()',
                'complete' => '$(".progress").hide()',
            ));
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 60, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        <li class="all <?php if ($all) echo 'disabled'; ?>">
            <?php
                if ($all):
                    echo '<span class="red">' . __('view all') . '</span>';
                else:
                    echo $this->Paginator->link(__('view all'), 'all');
                endif;
            ?>
        </li>
        </ul>
    </div>
<script type="text/javascript">
    var currentUri = "<?php echo isset($currentUri) ? h($currentUri) : '/events/viewEventAttributes/' . h($event['Event']['id']); ?>";
    var currentPopover = "";
    var ajaxResults = {"hover": [], "persistent": []};
    var timer;
    var lastSelected = false;
    var deleted = <?php echo (!empty($deleted)) ? '1' : '0';?>;
    var includeRelatedTags = <?php echo (!empty($includeRelatedTags)) ? '1' : '0';?>;
    $(document).ready(function() {
        $('.addGalaxy').click(function() {
            addGalaxyListener(this);
        });
        <?php
            if ($focusedRow !== false):
        ?>
            //window.location.hash = '.row_' + '<?php echo h($focusedRow); ?>';
            //$.scrollTo('#row_' + '<?php echo h($k); ?>', 800, {easing:'elasout'});
            //$('html,body').animate({scrollTop: $('#row_' + '<?php echo h($k); ?>').offset().top}, 'slow');
                $('.row_' + '<?php echo h($focusedRow); ?>').focus();
        <?php
            endif;
        ?>
        setContextFields();
        popoverStartup();
        $('.select_attribute').removeAttr('checked');
        $('.select_proposal').removeAttr('checked');
        $('.select_attribute').click(function(e) {
            if ($(this).is(':checked')) {
                if (e.shiftKey) {
                    selectAllInbetween(lastSelected, this.id);
                }
                lastSelected = this.id;
            }
            attributeListAnyAttributeCheckBoxesChecked();
        });
        $('.select_proposal').click(function(e){
            if ($(this).is(':checked')) {
                if (e.shiftKey) {
                    selectAllInbetween(lastSelected, this.id);
                }
                lastSelected = this.id;
            }
            attributeListAnyProposalCheckBoxesChecked();
        });
        $('.select_all').click(function() {
            attributeListAnyAttributeCheckBoxesChecked();
            attributeListAnyProposalCheckBoxesChecked();
        });
        $('.correlation-toggle').click(function() {
            var attribute_id = $(this).data('attribute-id');
            getPopup(attribute_id, 'attributes', 'toggleCorrelation', '', '#confirmation_box');
            return false;
        });
        $('.toids-toggle').click(function() {
            var attribute_id = $(this).data('attribute-id');
            getPopup(attribute_id, 'attributes', 'toggleToIDS', '', '#confirmation_box');
            return false;
        });
        $('.screenshot').click(function() {
            screenshotPopup($(this).attr('src'), $(this).attr('title'));
        });
        $('.sightings_advanced_add').click(function() {
            var selected = [];
            var object_context = $(this).data('object-context');
            var object_id = $(this).data('object-id');
            if (object_id == 'selected') {
                $(".select_attribute").each(function() {
                    if ($(this).is(":checked")) {
                        selected.push($(this).data("id"));
                    }
                });
                object_id = selected.join('|');
            }
            url = "<?php echo $baseurl; ?>" + "/sightings/advanced/" + object_id + "/" + object_context;
            genericPopup(url, '#popover_box');
        });
        $(".eventViewAttributeHover").mouseenter(function() {
            $('#' + currentPopover).popover('destroy');
            var type = $(this).attr('data-object-type');
            var id = $(this).attr('data-object-id');

            if (type + "_" + id in ajaxResults["hover"]) {
                var element = $('#' + type + '_' + id + '_container');
                element.popover({
                    title: attributeHoverTitle(id, type),
                    content: ajaxResults["hover"][type + "_" + id],
                    placement: attributeHoverPlacement(element),
                    html: true,
                    trigger: 'manual',
                    container: 'body'
                }).popover('show');
                currentPopover = type + '_' + id + '_container';
            } else {
              timer = setTimeout(function () {
                  runHoverLookup(type, id)
                },
                500
              );
            }
        }).mouseout(function() {
            clearTimeout(timer);
        });
    });
    $('#attributesFilterField').bind("keydown", function(e) {
        var eventid = $('#attributesFilterField').data("eventid");
        if ((e.keyCode == 13 || e.keyCode == 10)) {
            filterAttributes('value', eventid);
        }
    });
    $('.hex-value-convert').click(function() {
        var val = $(this).parent().children(':first-child').text();
        if ($(this).parent().children(':first-child').attr('data-original-title') == 'Hexadecimal representation') {
            var bin = [];
            var temp;
            val.split('').forEach(function(entry) {
                temp = parseInt(entry, 16).toString(2);
                bin.push(Array(5 - (temp.length)).join('0') + temp);
            });
            bin = bin.join(' ');
            $(this).parent().children(':first-child').text(bin);
            $(this).parent().children(':first-child').attr('data-original-title', 'Binary representation');
            $(this).parent().children(':nth-child(2)').attr('data-original-title', 'Switch to hexadecimal representation');
            $(this).parent().children(':nth-child(2)').attr('aria-label', 'Switch to hexadecimal representation');
        } else {
            val = val.split(' ');
            hex = '';
            val.forEach(function(entry) {
                hex += parseInt(entry , 2).toString(16).toUpperCase();
            });
            $(this).parent().children(':first-child').text(hex);
            $(this).parent().children(':first-child').attr('data-original-title', 'Hexadecimal representation');
            $(this).parent().children(':nth-child(2)').attr('data-original-title', 'Switch to binary representation');
            $(this).parent().children(':nth-child(2)').attr('aria-label', 'Switch to binary representation');
        }
    });
    $('.searchFilterButton').click(function() {
        filterAttributes('value', '<?php echo h($event['Event']['id']); ?>');
    });
    $('#quickFilterButton').click(function() {
        filterAttributes('value', '<?php echo h($event['Event']['id']); ?>');
    });
    $('#quickFilterField').on('keypress', function (e) {
        if(e.which === 13) {
            filterAttributes('value', '<?php echo h($event['Event']['id']); ?>');
        }
    });
</script>
<?php
    echo $this->Js->writeBuffer();
?>
