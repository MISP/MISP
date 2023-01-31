<?php
    echo $this->Tag->tags($entity->tags, [
        'allTags' => $allTags,
        'picker' => true,
        'editable' => true,
    ]);
