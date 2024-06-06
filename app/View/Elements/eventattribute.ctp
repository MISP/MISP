<?php
    $mayChangeCorrelation = $this->Acl->canDisableCorrelation($event);
    $possibleAction = $mayModify ? 'attribute' : 'shadow_attribute';
    $all = isset($this->params->params['paging']['Event']['page']) && $this->params->params['paging']['Event']['page'] == 0;
    $fieldCount = 10;
?>
    <div class="pagination">
        <ul>
        <?php
            $params = $this->request->named;
            if (isset($params['focus'])) {
                $focus = $params['focus'];
            }
            unset($params['focus']);
            $params += $advancedFilteringActiveRules;
            $url = array_merge(array('controller' => 'events', 'action' => 'viewEventAttributes', $event['Event']['id']), $params);
            $this->Paginator->options(array(
                'url' => $url,
                'data-paginator' => '#attributes_div',
            ));
            $paginatorLinks = $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            $paginatorLinks .= $this->Paginator->numbers(array('modulus' => 60, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
            $paginatorLinks .= $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $paginatorLinks;
        ?>
        <li class="all<?php if ($all) echo ' disabled'; ?>">
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
<div id="edit_object_div">
    <?php
        $deleteSelectedUrl = $baseurl . '/attributes/deleteSelected/' . $event['Event']['id'];
        if (empty($event['Event']['publish_timestamp'])) {
            $deleteSelectedUrl .= '/1';
        }
        echo $this->Form->create('Attribute', array('id' => 'delete_selected', 'url' => $deleteSelectedUrl));
        echo $this->Form->input('ids_delete', array(
            'type' => 'text',
            'value' => '',
            'style' => 'display:none;',
            'label' => false,
        ));
        echo $this->Form->end();

        echo $this->Form->create('ShadowAttribute', array('id' => 'accept_selected', 'url' => $baseurl . '/shadow_attributes/acceptSelected/' . $event['Event']['id']));
        echo $this->Form->input('ids_accept', array(
            'type' => 'text',
            'value' => '',
            'style' => 'display:none;',
            'label' => false,
        ));
        echo $this->Form->end();

        echo $this->Form->create('ShadowAttribute', array('id' => 'discard_selected', 'url' => $baseurl . '/shadow_attributes/discardSelected/' . $event['Event']['id']));
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
<div id="tempnotecontainer"></div>
<div id="attributeList">
    <?php
        echo $this->element('eventattributetoolbar', [
            'attributeFilter' => $attributeFilter,
            'mayModify' => $mayModify,
            'possibleAction' => $possibleAction
        ]);
    ?>
    <table class="table table-striped table-condensed">
        <tr>
            <?php
                if ($extended || ($mayModify && !empty($event['objects']))):
                    $fieldCount++;
            ?>
                    <th><input class="select_all" type="checkbox" title="<?php echo __('Select all');?>" role="button" tabindex="0" aria-label="<?php echo __('Select all attributes/proposals on current page');?>" onclick="toggleAllAttributeCheckboxes()"></th>
            <?php
                endif;
            ?>
            <th class="context hidden"><?php echo $this->Paginator->sort('id', 'ID');?></th>
            <th class="context hidden">UUID</th>
            <th class="context hidden"><?= $this->Paginator->sort('first_seen', __('First seen')) ?> <i class="fas fa-arrow-right"></i> <?= $this->Paginator->sort('last_seen', __('Last seen')) ?></th>
            <th><?php echo $this->Paginator->sort('timestamp', __('Date'), array('direction' => 'desc'));?></th>
            <th class="context"><?= __('Context') ?></th>
            <?php if ($extended): ?>
                <th class="event_id"><?php echo $this->Paginator->sort('event_id', __('Event'));?></th>
            <?php endif; ?>
            <?php if ($includeOrgColumn): $fieldCount++; ?>
            <th><?php echo $this->Paginator->sort('Org.name', __('Org')); ?>
            <?php endif; ?>
            <th><?php echo $this->Paginator->sort('category');?></th>
            <th><?php echo $this->Paginator->sort('type');?></th>
            <th><?php echo $this->Paginator->sort('value');?></th>
            <th><?php echo __('Tags');?></th>
            <?php
                if ($includeRelatedTags) {
                    echo sprintf('<th>%s</th>', __('Related Tags'));
                }
                $fieldCount++;
            ?>
            <th><?php echo __('Galaxies');?></th>
            <th><?php echo $this->Paginator->sort('comment');?></th>
            <th><?php echo __('Correlate');?></th>
            <th><?php echo __('Related Events');?></th>
            <?php if ($me['Role']['perm_view_feed_correlations']) { ?>
                <th><?php echo __('Feed hits');?></th>
            <?php } ?>
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
                    $fieldCount++;
                }
                if ($includeDecayScore) {
                    echo sprintf(
                        '<th class="decayingScoreField" title="%s">%s</th>',
                        __('Decaying Score'),
                        __('Score')
                    );
                    $fieldCount++;
                }
            ?>
            <th class="actions"><?php echo __('Actions');?></th>
        </tr>
        <?php
            foreach ($event['objects'] as $k => $object) {
                echo $this->element('/Events/View/row_' . $object['objectType'], array(
                    'object' => $object,
                    'k' => $k,
                    'mayModify' => $mayModify,
                    'mayChangeCorrelation' => $mayChangeCorrelation,
                    'fieldCount' => $fieldCount,
                ));
                if (
                    ($object['objectType'] === 'attribute' && !empty($object['ShadowAttribute'])) ||
                    $object['objectType'] === 'object'
                ):
        ?>
                    <tr class="blank_table_row"><td colspan="<?php echo $fieldCount; ?>"></td></tr>
        <?php
                endif;
            }
        ?>
    </table>
    <?php
    // Generate form for adding sighting just once, generation for every attribute is surprisingly too slow
    echo $this->Form->create('Sighting', ['id' => 'SightingForm', 'url' => $baseurl . '/sightings/add/', 'style' => 'display:none']);
    echo $this->Form->input('id', ['label' => false, 'type' => 'number']);
    echo $this->Form->input('type', ['label' => false]);
    echo $this->Form->end();
    ?>
</div>
    <?php if ($emptyEvent && (empty($attributeFilter) || $attributeFilter === 'all') && empty($passedArgsArray)): ?>
        <div class="background-red bold" style="padding: 2px 5px">
            <?php
                if ($me['org_id'] != $event['Event']['orgc_id']) {
                    echo __('Attribute warning: This event doesn\'t have any attributes visible to you. Either the owner of the event decided to have
a specific distribution scheme per attribute and wanted to still distribute the event alone either for notification or potential contribution with attributes without such restriction. Or the owner forgot to add the
attributes or the appropriate distribution level. If you think there is a mistake or you can contribute attributes based on the event meta-information, feel free to make a proposal');
                } else {
                    echo __('Attribute warning: This event doesn\'t contain any attribute. It\'s strongly advised to populate the event with attributes (indicators, observables or information) to provide a meaningful event');
                }
            ?>
        </div>
    <?php endif;?>
    <p>
        <?= $this->Paginator->counter([
            'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
        ]); ?>
    </p>
    <div class="pagination">
        <ul>
        <?= $paginatorLinks ?>
        <li class="all<?php if ($all) echo ' disabled'; ?>">
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
<script>
    var currentUri = "<?php echo isset($currentUri) ? h($currentUri) : $baseurl . '/events/viewEventAttributes/' . h($event['Event']['id']); ?>";
    var currentPopover = "";
    var ajaxResults = {"hover": [], "persistent": []};
    var lastSelected = false;
    var deleted = <?php echo (!empty($deleted)) ? '1' : '0';?>;
    var includeRelatedTags = <?php echo (!empty($includeRelatedTags)) ? '1' : '0';?>;
    $(document).ready(function() {
        $('.analyst-data-fetcher').click(function() {
            var $seed = $(this).data('seed');
            var $object_uuid = $(this).data('object-uuid');
            var $object_type = $(this).data('object-type');
            var $that = this;
            $.ajax({
                type: 'GET',
                url: baseurl + '/' + $object_type + '/viewAnalystData' + '/' + $object_uuid + '/' + $seed,
                success:function (data) {
                    $('#tempnotecontainer').html(data);
                    window['openNotes' + $seed]($that);
                }
            });
            
        });

        $('[data-toggle="quickcollapse"').click(function() {
            var $clicked = $(this)
            toggleVisibilityForAttributes($clicked)
        })
    });

    function toggleVisibilityForAttributes($button, show) {
        var targetClass = $button.data('target')
        var $targetElement = $(targetClass)
        var $textElement = $button.find('.text')
        var $iconElement = $button.find('.fa')
        var shouldShow = show !== undefined ? show : ($targetElement[0].style.display)
        if (shouldShow) {
            $targetElement.show()
            $textElement.text($textElement.data('text-hide'))
            $iconElement.addClass($iconElement.data('class-hide')).removeClass($iconElement.data('class-show'))
        } else {
            $targetElement.hide()
            $textElement.text($textElement.data('text-show'))
            $iconElement.addClass($iconElement.data('class-show')).removeClass($iconElement.data('class-hide'))
        }
    }

    function showAllAttributeInObjects() {
        $('[data-toggle="quickcollapse"').each(function() {
            toggleVisibilityForAttributes($(this), true)
        })
    }
    function hideAllAttributeInObjects() {
        $('[data-toggle="quickcollapse"').each(function() {
            toggleVisibilityForAttributes($(this), false)
        })
    }

    $(function() {
        <?php
            if (isset($focus)):
        ?>
        focusObjectByUuid('<?= h($focus); ?>');
        <?php
            endif;
        ?>
        popoverStartup();
        $('.select_attribute').prop('checked', false).click(function(e) {
            if ($(this).is(':checked')) {
                if (e.shiftKey) {
                    selectAllInbetween(lastSelected, this);
                }
                lastSelected = this;
            }
            attributeListAnyAttributeCheckBoxesChecked();
        });
        $('.select_proposal').prop('checked', false).click(function(e){
            if ($(this).is(':checked')) {
                if (e.shiftKey) {
                    selectAllInbetween(lastSelected, this);
                }
                lastSelected = this;
            }
            attributeListAnyProposalCheckBoxesChecked();
        });
        $('.select_all').click(function() {
            attributeListAnyAttributeCheckBoxesChecked();
            attributeListAnyProposalCheckBoxesChecked();
        });
    });
    $('.searchFilterButton, #quickFilterButton').click(function() {
        filterAttributes('value');
    });
</script>
