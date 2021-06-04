<?php
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'model' => 'Galaxy',
        'title' => sprintf(__('Export galaxy: %s'), h($galaxy['Galaxy']['name'])),
        'fields' => array(
            array(
                'field' => 'distribution',
                'label' => '<strong>' . __("Clusters' distribution:") . '</strong>',
                'options' => $distributionLevels,
                'selected' => array(1, 2, 3),
                'multiple' => 'checkbox', 
            ),
            '<br />',
            array(
                'field' => 'custom',
                'type' => 'checkbox',
                'label' => __("Include Custom Clusters"),
                'checked' => true
            ),
            array(
                'field' => 'default',
                'type' => 'checkbox',
                'label' => __("Include Default Clusters"),
                'checked' => true
            ),
            array(
                'field' => 'format',
                'type' => 'radio',
                'legend' => __('Export format'),
                'options' => array(
                    'misp' => sprintf('<b>%s</b>: %s', __('MISP Format'), __('To re-import in another MISP')),
                    'misp-galaxy' => sprintf('<b>%s</b>: %s', __('misp-galaxy format'), __('Usable to be integrated into the official repository')),
                ),
                'default' => 'misp',
            ),
            sprintf('<div id="misp-format-notice" class="alert hidden"><strong>%s</strong> %s</div>',__('Warning!'), __('The exported JSON will not contain the `category` key. Also, other keys such as `authors` and `version` may need to be adjusted manually.')),
            array(
                'field' => 'download',
                'type' => 'radio',
                'legend' => __('Export type'),
                'options' => array(
                    'download' => __('Download'),
                    'raw' => __('Raw'),
                ),
                'default' => 'raw',
            ),
        )
    )
));

echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'export'));
?>

<script>
$('#GalaxyFormatMispGalaxy').parent().find('input[type="radio"]').change(function() {
    if(this.checked && this.id == 'GalaxyFormatMispGalaxy') {
        $('#misp-format-notice').show()
    } else {
        $('#misp-format-notice').hide()
    }
})
</script>