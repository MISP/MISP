<?php
    $mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
    $mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
?>

<div class="attribute_creation">
    <?php echo $this->Form->create('Attribute');?>
        <fieldset>
            <legend><?php echo __('Add Attribute'); ?></legend>
            <div class="add_attribute_fields">
                <?php
                echo $this->Form->hidden('event_id');
                echo $this->Form->input('category', array(
                        'empty' => '(choose one)'
                        ));
                echo $this->Form->input('type', array(
                        'empty' => '(first choose category)'
                        ));

                $initialDistribution = 3;
                if (Configure::read('MISP.default_attribute_distribution') != null) {
                    if (Configure::read('MISP.default_attribute_distribution') === 'event') {
                        $initialDistribution = 5;
                    } else {
                        $initialDistribution = Configure::read('MISP.default_attribute_distribution');
                    }
                }
                echo $this->Form->input('distribution', array(
                    'options' => array($distributionLevels),
                    'label' => __('Distribution'),
                    'selected' => $initialDistribution,
                ));

                echo $this->Form->input('value', array(
                        'type' => 'textarea',
                        'error' => array('escape' => false),
                        'div' => 'input clear',
                        'class' => 'input-xxlarge'
                ));
                echo $this->Form->input('comment', array(
                        'type' => 'text',
                        'label' => __('Contextual Comment'),
                        'error' => array('escape' => false),
                        'div' => 'input clear',
                        'class' => 'input-xxlarge'
                ));
                ?>
                <div class="input clear"></div>
                <?php
                echo $this->Form->input('to_ids', array(
                            'checked' => false,
                            'data-content' => isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc'],
                            'label' => __('for Intrusion Detection System'),
                ));
                echo $this->Form->input('batch_import', array(
                        'type' => 'checkbox',
                        'data-content' => __('Create multiple attributes one per line'),
                ));
                // link an onchange event to the form elements
                $this->Js->get('#AttributeCategory')->event('change', 'formCategoryChanged("#AttributeCategory")');
                ?>
            </div>
        </fieldset>
        <div class="overlay_spacing">
            <table>
                <tr>
                <td style="vertical-align:top">
                    <?php
                    echo $this->Js->submit('Submit', array(
                            'before'=>$this->Js->get('#loading')->effect('fadeIn'),
                            'success'=>$this->Js->get('#loading')->effect('fadeOut'),
                            'complete'=> $this->Js->request(
                                    array('action' => 'view', $event['Event']['id'], 'attributesPage:' . $page),
                                    array(
                                            'update' => '#attributes_div',
                                            'before' => '$(".loading").show();$("#gray_out").hide();$("#attribute_creation_div").hide();',
                                            'complete' => '$(".loading").hide();',
                                    )
                            ),
                            'class'=>'btn btn-primary',
                            'url' => '/attributes/add/' . $event['Event']['id']
                    ));
                    ?>
                </td>
                <td style="width:540px;">
                    <p style="color:red;font-weight:bold;display:none;text-align:center" id="warning-message"><?php echo __('Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.');?></p>
                </td>
                <td style="vertical-align:top;">
                    <span class="btn btn-inverse" id="cancel_attribute_add"><?php echo __('Cancel');?></span>
                </td>
                </tr>
            </table>
        </div>
    <?php
        echo $this->Form->end();
    ?>

    <script type="text/javascript">
    //
    //Generate Category / Type filtering array
    //
    var category_type_mapping = new Array();
    <?php
    foreach ($categoryDefinitions as $category => $def) {
        echo "category_type_mapping['" . addslashes($category) . "'] = {";
        $first = true;
        foreach ($def['types'] as $type) {
            if ($first) $first = false;
            else echo ', ';
            echo "'" . addslashes($type) . "' : '" . addslashes($type) . "'";
        }
        echo "}; \n";
    }
    ?>
    function formCategoryChanged(id) {
        // fill in the types
        var options = $('#AttributeType').prop('options');
        $('option', $('#AttributeType')).remove();
        $.each(category_type_mapping[$('#AttributeCategory').val()], function(val, text) {
            options[options.length] = new Option(text, val);
        });
        // enable the form element
        $('#AttributeType').prop('disabled', false);
    }


    //
    // Generate tooltip information
    //
    var formInfoValues = new Array();
    <?php
    foreach ($typeDefinitions as $type => $def) {
        $info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
        echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
    }
    foreach ($categoryDefinitions as $category => $def) {
        $info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
        echo "formInfoValues['" . addslashes($category) . "'] = \"" . addslashes($info) . "\";\n"; // as we output JS code we need to add slashes
    }
    foreach ($distributionDescriptions as $type => $def) {
        $info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
        echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
    }
    ?>

    $(document).ready(function() {

        $("#AttributeType, #AttributeCategory, #Attribute, #AttributeDistribution").on('mouseover', function(e) {
            var $e = $(e.target);
            if ($e.is('option')) {
                $('#'+e.currentTarget.id).popover('destroy');
                $('#'+e.currentTarget.id).popover({
                    trigger: 'focus',
                    placement: 'right',
                    container: 'body',
                    content: formInfoValues[$e.val()],
                }).popover('show');
            }
        });

        $("input, label").on('mouseleave', function(e) {
            $('#'+e.currentTarget.id).popover('destroy');
        });

        $("input, label").on('mouseover', function(e) {
            var $e = $(e.target);
            $('#'+e.currentTarget.id).popover('destroy');
            $('#'+e.currentTarget.id).popover({
                trigger: 'focus',
                placement: 'right',
                container: 'body',
            }).popover('show');

        });

        // workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
        // disadvangate is that user needs to click on the item to see the tooltip.
        // no solutions exist, except to generate the select completely using html.
        $("#AttributeType, #AttributeCategory, #Attribute, #AttributeDistribution").on('change', function(e) {
            if (this.id === "AttributeCategory") {
                var select = document.getElementById("AttributeCategory");
                if (select.value === 'Attribution' || select.value === 'Targeting data') {
                    $("#warning-message").show();
                } else {
                    $("#warning-message").hide();
                }
            }
            var $e = $(e.target);
            $('#'+e.currentTarget.id).popover('destroy');
            $('#'+e.currentTarget.id).popover({
                trigger: 'focus',
                placement: 'right',
                container: 'body',
                content: formInfoValues[$e.val()],
            }).popover('show');
        });

        $('#cancel_attribute_add').click(function() {
            $('#gray_out').hide();
            $('#attribute_creation_div').hide();
        });
    });
    </script>
</div>
<?php
    echo $this->Js->writeBuffer();
?>
