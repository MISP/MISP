<?php

if (empty($limits)) {
    $limits = [10 => 10, 25 => 25, 50 => 50];
}

if (empty($selectedOption)) {
    $selectedOption = false;
}

echo $this->Paginator->limitControl($limits, $selectedOption);
