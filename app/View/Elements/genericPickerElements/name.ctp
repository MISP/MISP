<?php
if (is_array($name)) {
    if (isset($name['label'])) {
        $label = $name['label'];
        $name = $name['name'];
        $background_color = isset($label['background']) ? h($label['background']) : '#ffffff';
        $color = isset($label['background']) ? $this->TextColour->getTextColour($label['background']) : '#0088cc';
?>
        <span href="#" class="tagComplete" style="background-color:<?php echo h($background_color); ?>; color:<?php echo h($color); ?>">
            <?php echo h($name) ?>
        </span>
<?php
    } else {
        echo h($name);
    }
} else {
    echo h($name);
}
