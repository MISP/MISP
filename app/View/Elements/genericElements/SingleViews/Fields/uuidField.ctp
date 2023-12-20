<?php
    $uuid = Hash::extract($data, $field['path'])[0];
    echo sprintf(
        '<span class="quickSelect">%s</span>',
        h($uuid)
    );

    $object_uuid = 'bf74e1a4-99c2-4fcb-8a5d-a71118effd1a';
    $object_type = 'event';
    $notes = [
        [
            'analyst_note' => 'This is a note',
            'note_type' => 0,
            'authors' => ['adulau', 'iglocska'],
            'org_uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0',
            'orgc_uuid' => '27e68e2e-c7a9-4aba-9949-ca3383facb24',
            'Organisation' => ['id' => 23, 'uuid' => '27e68e2e-c7a9-4aba-9949-ca3383facb24', 'name' => 'ORG_1'],
            'created' => new DateTime(),
            'modified' => new DateTime(),
            'distribution' => 2,
            'id' => 1,
            'uuid' => '91bc1aa1-2322-43b9-9aad-c0262e6248b3',
            'object_uuid' => 'bf74e1a4-99c2-4fcb-8a5d-a71118effd1a'
        ],
        [
            'analyst_note' => 'This is another note',
            'note_type' => 0,
            'authors' => ['mokaddem',],
            'org_uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0',
            'orgc_uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0',
            'Organisation' => ['id' => 2, 'uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0', 'name' => 'CIRCL'],
            'created' => new DateTime(),
            'modified' => new DateTime(),
            'distribution' => 3,
            'id' => 2,
            'uuid' => '5a019778-6f0f-4e80-94c5-2e9ec33c9a92',
            'object_uuid' => 'bf74e1a4-99c2-4fcb-8a5d-a71118effd1a',
            'notes' => [
                [
                    'opinion' => 10,
                    'comment' => 'This is analysis is really bad!',
                    'note_type' => 1,
                    'authors' => ['chrisr3d',],
                    'org_uuid' => '27e68e2e-c7a9-4aba-9949-ca3383facb24',
                    'orgc_uuid' => '27e68e2e-c7a9-4aba-9949-ca3383facb24',
                    'Organisation' => ['id' => 23, 'uuid' => '27e68e2e-c7a9-4aba-9949-ca3383facb24', 'name' => 'ORG_1'],
                    'created' => new DateTime(),
                    'modified' => new DateTime(),
                    'distribution' => 2,
                    'id' => 6,
                    'uuid' => 'a3aca875-e5d8-4b74-8a2f-63100f17afe0',
                    'object_uuid' => 'bf74e1a4-99c2-4fcb-8a5d-a71118effd1a',
                    'notes' => [
                        [
                            'opinion' => 100,
                            'comment' => 'No! It\'s really good!',
                            'note_type' => 1,
                            'authors' => ['chrisr3d',],
                            'org_uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0',
                            'orgc_uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0',
                            'Organisation' => ['id' => 2, 'uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0', 'name' => 'CIRCL'],
                            'created' => new DateTime(),
                            'modified' => new DateTime(),
                            'distribution' => 2,
                            'id' => 7,
                            'uuid' => '4d8585ea-bf5a-42c2-876b-02b6c9f470e0',
                            'object_uuid' => 'bf74e1a4-99c2-4fcb-8a5d-a71118effd1a'
                        ],
                    ]
                ],
                [
                    'opinion' => 70,
                    'comment' => 'After further analysis, it\'s OK.',
                    'note_type' => 1,
                    'authors' => ['chrisr3d',],
                    'org_uuid' => '27e68e2e-c7a9-4aba-9949-ca3383facb24',
                    'orgc_uuid' => '27e68e2e-c7a9-4aba-9949-ca3383facb24',
                    'Organisation' => ['id' => 23, 'uuid' => '27e68e2e-c7a9-4aba-9949-ca3383facb24', 'name' => 'ORG_1'],
                    'created' => new DateTime(),
                    'modified' => new DateTime(),
                    'distribution' => 0,
                    'id' => 8,
                    'uuid' => 'a3aca875-e5d8-4b74-8a2f-63100f17afe0',
                    'object_uuid' => 'bf74e1a4-99c2-4fcb-8a5d-a71118effd1a',
                ],
            ]
        ],
        [
            'opinion' => 80,
            'comment' => 'This is a second opinion',
            'note_type' => 1,
            'authors' => ['mokaddem',],
            'org_uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0',
            'orgc_uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0',
            'Organisation' => ['id' => 3, 'uuid' => '5d6d3b30-9db0-44b9-8869-7f56a5e38e14', 'name' => 'Training'],
            'created' => new DateTime(),
            'modified' => new DateTime(),
            'distribution' => 3,
            'id' => 4,
            'uuid' => '41c2ad07-4529-4014-ab8c-0a3f0d6fccc1',
            'object_uuid' => 'bf74e1a4-99c2-4fcb-8a5d-a71118effd1a'
        ],
        [
            'opinion' => 45,
            'comment' => 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
            'note_type' => 1,
            'authors' => ['mokaddem',],
            'org_uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0',
            'orgc_uuid' => '1646fb8f-6f23-4b51-ae80-c84d1ff8fbe0',
            'Organisation' => ['id' => 3, 'uuid' => '5d6d3b30-9db0-44b9-8869-7f56a5e38e14', 'name' => 'Training'],
            'created' => new DateTime(),
            'modified' => new DateTime(),
            'distribution' => 3,
            'id' => 5,
            'uuid' => '24957461-344c-4b7e-81fe-1321f3e9949a',
            'object_uuid' => 'bf74e1a4-99c2-4fcb-8a5d-a71118effd1a'
        ],
    ];

    if (!empty($notes)) {
        echo $this->element('genericElements/Analyst_notes/notes', ['notes' => $notes, 'object_uuid' => $object_uuid, 'object_type' => $object_type]);
    }
