<?php
echo sprintf(
    '<div%s%s%s></div>',
    isset($fieldData['id']) ? sprintf(' id="%s"', h($fieldData['id'])) : '',
    isset($fieldData['class']) ? sprintf(' class="%s"', h($fieldData['class'])) : '',
    isset($fieldData['style']) ? sprintf(' style="%s"', h($fieldData['style'])) : ''
);
