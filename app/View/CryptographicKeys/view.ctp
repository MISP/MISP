<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Cryptographic key view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('type'),
                'path' => 'CryptographicKey.type'
            ],
            [
                'key' => __('key_data'),
                'path' => 'CryptographicKey.key_data'
            ]
        ]
    ]
);
