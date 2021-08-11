<?php

if (!empty($data['TemplateTag'])) {
    foreach ($data['TemplateTag'] as $tag) {
?>
        <span class="tagComplete" style="background-color:<?php echo h($tag['Tag']['colour']); ?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']); ?>"><?php echo h($tag['Tag']['name']); ?></span>
<?php
    }
} else echo '&nbsp';
