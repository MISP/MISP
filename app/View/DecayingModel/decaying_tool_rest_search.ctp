<div id="attribute_div">
    <div class="pagination" style="margin: 0px;">
        <ul>
        <?php
            $this->Paginator->options(array(
                'update' => '#attribute_div',
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
            'ID',
            $this->Paginator->sort('event_id'),

            $this->Paginator->sort('date'),
            $this->Paginator->sort('Event.orgc_id', __('Org')),
            $this->Paginator->sort('category'),
            $this->Paginator->sort('type'),
            $this->Paginator->sort('value'),
            __('Tags'),
            __('Event Tags'),
            __('Galaxies'),
            $this->Paginator->sort('comment'),
            sprintf('<span title="%s">%s', $attrDescriptions['signature']['desc'], $this->Paginator->sort('IDS')),
            __('Sightings')
        );
        foreach ($headers as $k => &$header) {
            $header = sprintf('<th>%s</th>', $header);
        }
        $header = sprintf('<thead><tr>%s</tr></thead>', implode('', $headers));
        $rows = array();
        foreach ($attributes as $k => $attribute) {
            $event = array(
                'Event' => $attribute['Event'],
                'Orgc' => $attribute['Event']['Orgc'],
            );
            $rows[] =  $this->element('DecayingModels/View/row_attribute_simulation', array(
                'object' => $attribute['Attribute'],
                'event' => $event
            ));
        }
        echo sprintf('<table class="table table-striped table-hover table-condensed">%s %s</table>', $header, implode('', $rows));
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

<script>
    $(document).ready(function() {
        $('#attribute_div .pagination a').click(function(e) {
            var url = this.href;
            $.ajax({
                beforeSend:function() {
                    $('#attributeTableContainer').html('<div style="height:100%; display:flex; align-items:center; justify-content:center;"><span class="fa fa-spinner fa-spin" style="font-size: xx-large;"></span></div>');
                },
                success:function (data, textStatus) {
                    $('#attributeTableContainer').html(data);
                },
                error:function() {
                    showMessage('fail', '<?php echo __('Failed to perform RestSearch') ?>');
                },
                type:'get',
                url: url,
            });
            return false;
        });
    });
</script>
