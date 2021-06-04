<?php
    foreach ($side_panels as $side_panel) {
        echo $this->element(
            '/genericElements/SidePanels/Templates/' . $side_panel['type'],
            [
                'side_panel' => $side_panel
            ]
        );
    }

?>
