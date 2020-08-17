<div class="attributes index">
    <h2><?php echo __('Attributes'); ?></h2>
        <?php
            if ($isSearch == 1) {
                // The following block should serve as an example and food
                // for thought on how to optimize i18n & l10n (especially for languages that are not SOV)
                $filterOptions = array(
                    'value' => __(" with the value containing "),
                    'tags' => __(" being tagged with "),
                    'id' => __(" from the events "),
                    'tag' => __(" carrying the tag(s) "),
                    'type' => __(" of type "),
                    'category' => __(" of category "),
                    'org' => __(" created by organisation ")
                );
                $temp = '';
                foreach ($filterOptions as $fo => $text) {
                    if (!empty($filters[$fo])) {
                        $filter_options_string = $filters[$fo];
                        if (is_array($filter_options_string)) {
                            $filter_options_string = implode(' OR ', $filter_options_string);
                        }
                        $temp .= sprintf('%s <b>%s</b>', $text, h($filter_options_string));
                    }
                }
                echo sprintf("<h4>%s%s</h4>", __("Results for all attributes"), $temp);
            }
        ?>
    <div class="pagination">
        <ul>
        <?php
        $this->Paginator->options(array(
            'update' => '.span12',
            'evalScripts' => true,
            'before' => '$(".progress").show()',
            'complete' => '$(".progress").hide()',
        ));

            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
    <?php
        $headers = array(
            $this->Paginator->sort('timestamp', __('Date')),
            $this->Paginator->sort('event_id'),
            $this->Paginator->sort('Event.orgc_id', __('Org')),
            $this->Paginator->sort('category'),
            $this->Paginator->sort('type'),
            $this->Paginator->sort('value'),
            __('Tags'),
            __('Galaxies'),
            $this->Paginator->sort('comment'),
            __('Correlate'),
            __('Related Events'),
            __('Feed hits'),
            sprintf('<span title="%s">%s', $attrDescriptions['signature']['desc'], $this->Paginator->sort('IDS')),
            sprintf('<span title="%s">%s', $attrDescriptions['distribution']['desc'], $this->Paginator->sort('distribution')),
            __('Sightings'),
            __('Activity'),
            __('Actions')
        );
        foreach ($headers as $k => &$header) {
            $header = sprintf('<th>%s</th>', $header);
        }
        $rows = array(
            sprintf('<tr>%s</tr>', implode('', $headers))
        );
        $currentCount = 0;
        if ($isSearch == 1) {
            // sanitize data
            $toHighlight = array('value', 'comment');
            $keywordArray = array();
            foreach ($toHighlight as $highlightedElement) {
                if (!empty($filters[$highlightedElement])) {
                    if (!is_array($filters[$highlightedElement])) {
                        $filters[$highlightedElement] = array($filters[$highlightedElement]);
                    }
                    foreach ($filters[$highlightedElement] as $highlightedString) {
                        $keywordArray[] = $highlightedString;
                    }
                }
            }
            // build the $replacePairs variable used to highlight the keywords
            $replacePairs = $this->Highlight->build_replace_pairs($keywordArray);
        }
        foreach ($attributes as $k => $attribute) {
            $event = array(
                'Event' => $attribute['Event'],
                'Orgc' => $attribute['Event']['Orgc'],
            );
            $mayModify = ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id'] && $attribute['Event']['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $attribute['Event']['orgc_id'] == $me['org_id']));
            $mayPublish = ($isAclPublish && $attribute['Event']['orgc_id'] == $me['org_id']);
            $mayChangeCorrelation = !Configure::read('MISP.completely_disable_correlation') && ($isSiteAdmin || ($mayModify && Configure::read('MISP.allow_disabling_correlation')));
            $mayModify = $attribute['Event']['orgc_id'] === $me['org_id'] ? true : false;
            if (!empty($attribute['Attribute']['RelatedAttribute'])) {
                $event['RelatedAttribute'] = array($attribute['Attribute']['id'] => $attribute['Attribute']['RelatedAttribute']);
            }
            $rows[] =  $this->element('/Events/View/row_attribute', array(
                'object' => $attribute['Attribute'],
                'k' => $k,
                'mayModify' => $mayModify,
                'mayChangeCorrelation' => $mayChangeCorrelation,
                'page' => 1,
                'fieldCount' => 11,
                'includeRelatedTags' => 0,
                'event' => $event,
                'me' => $me,
                'extended' => 1,
                'disable_multi_select' => 1,
                'context' => 'list'
            ));
        }
        echo sprintf('<table class="table table-striped table-hover table-condensed">%s</table>', implode('', $rows));
    ?>
    <p>
    <?php
    echo $this->Paginator->counter(array(
    'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
    ));
    ?>
    </p>
    <div class="pagination">
        <ul>
        <?php
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
</div>
<?php
if ($isSearch == 1){
    $class = 'searchAttributes2';
} else {
    $class = 'listAttributes';
}
?>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => $class));
?>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
    $("td, div").tooltip({
        'placement': 'top',
        'container' : 'body',
        delay: { show: 500, hide: 100 }
    });
    $('.screenshot').click(function() {
        screenshotPopup($(this).attr('src'), $(this).attr('title'));
    });
    $('.addGalaxy').click(function() {
        addGalaxyListener(this);
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
    popoverStartup();
    $(document).on('click', function (e) {
        //did not click a popover toggle or popover
        if ($(e.target).data('toggle') !== 'popover'
            && $(e.target).parents('.popover.in').length === 0) {
            // filter for only defined popover
            var definedPopovers = $('[data-toggle="popover"]').filter(function(i, e) {
                    return $(e).data('popover') !== undefined;
            });
            definedPopovers.popover('hide');
        }
    });
});
</script>
