<?php

declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class TemplateElementAttributesSeeder extends AbstractSeed
{
    public function run(): void
    {
        $data = [
            ['id' => 1, 'template_element_id' => 1, 'name' => 'From address', 'description' => 'The source address from which the e-mail was sent.', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'email-src', 'mandatory' => 1, 'batch' => 1],
            ['id' => 2, 'template_element_id' => 2, 'name' => 'Malicious url', 'description' => 'The malicious url in the e-mail body.', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'url', 'mandatory' => 1, 'batch' => 1],
            ['id' => 3, 'template_element_id' => 4, 'name' => 'E-mail subject', 'description' => 'The subject line of the e-mail.', 'to_ids' => 0, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'email-subject', 'mandatory' => 1, 'batch' => 0],
            ['id' => 4, 'template_element_id' => 6, 'name' => 'Spoofed source address', 'description' => 'If an e-mail address was spoofed, specify which.', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'email-src', 'mandatory' => 0, 'batch' => 0],
            ['id' => 5, 'template_element_id' => 7, 'name' => 'Source IP', 'description' => 'The source IP from which the e-mail was sent', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'ip-src', 'mandatory' => 0, 'batch' => 1],
            ['id' => 6, 'template_element_id' => 8, 'name' => 'X-mailer header', 'description' => 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'text', 'mandatory' => 0, 'batch' => 1],
            ['id' => 7, 'template_element_id' => 12, 'name' => 'From address', 'description' => 'The source address from which the e-mail was sent', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'email-src', 'mandatory' => 1, 'batch' => 1],
            ['id' => 8, 'template_element_id' => 15, 'name' => 'Spoofed From Address', 'description' => 'The spoofed source address from which the e-mail appears to be sent.', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'email-src', 'mandatory' => 0, 'batch' => 1],
            ['id' => 9, 'template_element_id' => 17, 'name' => 'E-mail Source IP', 'description' => 'The IP address from which the e-mail was sent.', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'ip-src', 'mandatory' => 0, 'batch' => 1],
            ['id' => 10, 'template_element_id' => 18, 'name' => 'X-mailer header', 'description' => 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'text', 'mandatory' => 0, 'batch' => 0],
            ['id' => 11, 'template_element_id' => 19, 'name' => 'Malicious URL in the e-mail', 'description' => 'If there was a malicious URL (or several), please specify it here', 'to_ids' => 1, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'ip-dst', 'mandatory' => 0, 'batch' => 1],
            ['id' => 12, 'template_element_id' => 20, 'name' => 'Exploited vulnerablity', 'description' => 'The vulnerabilities exploited during the payload delivery.', 'to_ids' => 0, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'vulnerability', 'mandatory' => 0, 'batch' => 1],
            ['id' => 13, 'template_element_id' => 22, 'name' => 'C2 information', 'description' => 'Command and Control information detected during the analysis.', 'to_ids' => 1, 'category' => 'Network activity', 'complex' => 1, 'type' => 'CnC', 'mandatory' => 0, 'batch' => 1],
            ['id' => 14, 'template_element_id' => 23, 'name' => 'Artifacts dropped (File)', 'description' => 'Any information about the files dropped during the analysis', 'to_ids' => 1, 'category' => 'Artifacts dropped', 'complex' => 1, 'type' => 'File', 'mandatory' => 0, 'batch' => 1],
            ['id' => 15, 'template_element_id' => 24, 'name' => 'Artifacts dropped (Registry key)', 'description' => 'Any registry keys touched during the analysis', 'to_ids' => 1, 'category' => 'Artifacts dropped', 'complex' => 0, 'type' => 'regkey', 'mandatory' => 0, 'batch' => 1],
            ['id' => 16, 'template_element_id' => 25, 'name' => 'Artifacts dropped (Registry key + value)', 'description' => 'Any registry keys created or altered together with the value.', 'to_ids' => 1, 'category' => 'Artifacts dropped', 'complex' => 0, 'type' => 'regkey|value', 'mandatory' => 0, 'batch' => 1],
            ['id' => 17, 'template_element_id' => 26, 'name' => 'Persistance mechanism (filename)', 'description' => 'Filenames (or filenames with filepaths) used as a persistence mechanism', 'to_ids' => 1, 'category' => 'Persistence mechanism', 'complex' => 0, 'type' => 'regkey|value', 'mandatory' => 0, 'batch' => 1],
            ['id' => 18, 'template_element_id' => 27, 'name' => 'Persistence mechanism (Registry key)', 'description' => 'Any registry keys touched as part of the persistence mechanism during the analysis ', 'to_ids' => 1, 'category' => 'Persistence mechanism', 'complex' => 0, 'type' => 'regkey', 'mandatory' => 0, 'batch' => 1],
            ['id' => 19, 'template_element_id' => 28, 'name' => 'Persistence mechanism (Registry key + value)', 'description' => 'Any registry keys created or modified together with their values used by the persistence mechanism', 'to_ids' => 1, 'category' => 'Persistence mechanism', 'complex' => 0, 'type' => 'regkey|value', 'mandatory' => 0, 'batch' => 1],
            ['id' => 20, 'template_element_id' => 34, 'name' => 'C2 Information', 'description' => 'You can drop any urls, domains, hostnames or IP addresses that were detected as the Command and Control during the analysis here.', 'to_ids' => 1, 'category' => 'Network activity', 'complex' => 1, 'type' => 'CnC', 'mandatory' => 0, 'batch' => 1],
            ['id' => 21, 'template_element_id' => 35, 'name' => 'Other Network Activity', 'description' => 'Drop any applicable information about other network activity here. The attributes created here will NOT be marked for IDS exports.', 'to_ids' => 0, 'category' => 'Network activity', 'complex' => 1, 'type' => 'CnC', 'mandatory' => 0, 'batch' => 1],
            ['id' => 22, 'template_element_id' => 36, 'name' => 'Vulnerability', 'description' => 'The vulnerability or vulnerabilities that the sample exploits', 'to_ids' => 0, 'category' => 'Payload delivery', 'complex' => 0, 'type' => 'vulnerability', 'mandatory' => 0, 'batch' => 1],
            ['id' => 23, 'template_element_id' => 37, 'name' => 'Artifacts Dropped (File)', 'description' => 'Insert any data you have on dropped files here.', 'to_ids' => 1, 'category' => 'Artifacts dropped', 'complex' => 1, 'type' => 'File', 'mandatory' => 0, 'batch' => 1],
            ['id' => 24, 'template_element_id' => 38, 'name' => 'Artifacts dropped (Registry key)', 'description' => 'Any registry keys touched during the analysis', 'to_ids' => 1, 'category' => 'Artifacts dropped', 'complex' => 0, 'type' => 'regkey', 'mandatory' => 0, 'batch' => 1],
            ['id' => 25, 'template_element_id' => 39, 'name' => 'Artifacts dropped (Registry key + value)', 'description' => 'Any registry keys created or altered together with the value.', 'to_ids' => 1, 'category' => 'Artifacts dropped', 'complex' => 0, 'type' => 'regkey|value', 'mandatory' => 0, 'batch' => 1],
            ['id' => 26, 'template_element_id' => 42, 'name' => 'Persistence mechanism (filename)', 'description' => 'Insert any filenames used by the persistence mechanism.', 'to_ids' => 1, 'category' => 'Persistence mechanism', 'complex' => 0, 'type' => 'filename', 'mandatory' => 0, 'batch' => 1],
            ['id' => 27, 'template_element_id' => 43, 'name' => 'Persistence Mechanism (Registry key)', 'description' => 'Paste any registry keys that were created or modified as part of the persistence mechanism', 'to_ids' => 1, 'category' => 'Persistence mechanism', 'complex' => 0, 'type' => 'regkey', 'mandatory' => 0, 'batch' => 1],
            ['id' => 28, 'template_element_id' => 44, 'name' => 'Persistence Mechanism (Registry key and value)', 'description' => 'Paste any registry keys together with the values contained within created or modified by the persistence mechanism', 'to_ids' => 1, 'category' => 'Persistence mechanism', 'complex' => 0, 'type' => 'regkey|value', 'mandatory' => 0, 'batch' => 1],
            ['id' => 29, 'template_element_id' => 46, 'name' => 'Network Indicators', 'description' => 'Paste any combination of IP addresses, hostnames, domains or URL', 'to_ids' => 1, 'category' => 'Network activity', 'complex' => 1, 'type' => 'CnC', 'mandatory' => 0, 'batch' => 1],
            ['id' => 30, 'template_element_id' => 47, 'name' => 'File Indicators', 'description' => 'Paste any file hashes that you have (MD5, SHA1, SHA256) or filenames below. You can also add filename and hash pairs by using the following syntax for each applicable column: filename|hash ', 'to_ids' => 1, 'category' => 'Payload installation', 'complex' => 1, 'type' => 'File', 'mandatory' => 0, 'batch' => 1]
        ];


        $templateElementAttributes = $this->table('template_element_attributes');
        $templateElementAttributes->insert($data)
            ->saveData();
    }
}
