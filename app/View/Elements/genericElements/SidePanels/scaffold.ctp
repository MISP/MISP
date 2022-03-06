<?php
    foreach ($side_panels as $side_panel) {
        if (!isset($side_panel['requirement']) || $side_panel['requirement']) {
            echo $this->element(
                '/genericElements/SidePanels/Templates/' . $side_panel['type'],
                [
                    'side_panel' => $side_panel
                ]
            );
        }
    }
