<?php

declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class RegexpSeeder extends AbstractSeed
{
    public function run(): void
    {
        $data = [
            [
                'id'    => 1,
                'regexp' => '/.:.ProgramData./i',
                'replacement' => '%ALLUSERSPROFILE%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 2,
                'regexp' => '/.:.Documents and Settings.All Users./i',
                'replacement' => '%ALLUSERSPROFILE%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 3,
                'regexp' => '/.:.Program Files.Common Files./i',
                'replacement' => '%COMMONPROGRAMFILES%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 4,
                'regexp' => '/.:.Program Files (x86).Common Files./i',
                'replacement' => '%COMMONPROGRAMFILES(x86)%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 5,
                'regexp' => '/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i',
                'replacement' => '%TEMP%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 6,
                'regexp' => '/.:.ProgramData./i',
                'replacement' => '%PROGRAMDATA%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 7,
                'regexp' => '/.:.Program Files./i',
                'replacement' => '%PROGRAMFILES%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 8,
                'regexp' => '/.:.Program Files (x86)./i',
                'replacement' => '%PROGRAMFILES(X86)%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 9,
                'regexp' => '/.:.Users.Public./i',
                'replacement' => '%PUBLIC%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 10,
                'regexp' => '/.:.Documents and Settings\\\\(.*?)\\\\Local Settings.Temp./i',
                'replacement' => '%TEMP%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 11,
                'regexp' => '/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i',
                'replacement' => '%TEMP%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 12,
                'regexp' => '/.:.Users\\\\(.*?)\\\\AppData.Local./i',
                'replacement' => '%LOCALAPPDATA%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 13,
                'regexp' => '/.:.Users\\\\(.*?)\\\\AppData.Roaming./i',
                'replacement' => '%APPDATA%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 14,
                'regexp' => '/.:.Users\\\\(.*?)\\\\Application Data./i',
                'replacement' => '%APPDATA%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 15,
                'regexp' => '/.:.Windows\\\\(.*?)\\\\Application Data./i',
                'replacement' => '%APPDATA%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 16,
                'regexp' => '/.:.Users\\\\(.*?)\\\\/i',
                'replacement' => '%USERPROFILE%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 17,
                'regexp' => '/.:.DOCUME~1.\\\\(.*?)\\\\/i',
                'replacement' => '%USERPROFILE%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 18,
                'regexp' => '/.:.Documents and Settings\\\\(.*?)\\\\/i',
                'replacement' => '%USERPROFILE%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 19,
                'regexp' => '/.:.Windows./i',
                'replacement' => '%WINDIR%\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 20,
                'regexp' => '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}/i',
                'replacement' => 'HKCU',
                'type' => 'ALL',
            ],
            [
                'id'    => 21,
                'regexp' => '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}/i',
                'replacement' => 'HKCU',
                'type' => 'ALL',
            ],
            [
                'id'    => 22,
                'regexp' => '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}/i',
                'replacement' => 'HKCU',
                'type' => 'ALL',
            ],
            [
                'id'    => 23,
                'regexp' => '/.REGISTRY.MACHINE./i',
                'replacement' => 'HKLM\\\\',
                'type' => 'ALL',
            ],
            [
                'id'    => 24,
                'regexp' => '/%USERPROFILE%.Application Data.Microsoft.UProof/i',
                'replacement' => '',
                'type' => 'ALL',
            ],
            [
                'id'    => 25,
                'regexp' => '/%USERPROFILE%.Local Settings.History/i',
                'replacement' => '',
                'type' => 'ALL',
            ],
            [
                'id'    => 26,
                'regexp' => '/%APPDATA%.Microsoft.UProof/i',
                'replacement' => '',
                'type' => 'ALL',
            ],
            [
                'id'    => 27,
                'regexp' => '/%LOCALAPPDATA%.Microsoft.Windows.Temporary Internet Files/i',
                'replacement' => '',
                'type' => 'ALL',
            ],
        ];

        $regexp = $this->table('regexp');
        $regexp->insert($data)
            ->saveData();
    }
}
