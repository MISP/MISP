<?php

echo isset($data['Organisation']['id']) ? $this->OrgImg->getNameWithImg($data) : __('Unknown');
