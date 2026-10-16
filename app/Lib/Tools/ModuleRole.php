<?php

/**
 * Which expansion modules are not enrichment.
 *
 * `module-type: expansion` is what misp-modules calls anything the
 * attribute menu can hand a value to, and that is wider than *ask the
 * outside world about this value*. Read off misp-modules on
 * 2026-09-30, three families declare it and are not enrichment:
 *
 * - **submitters and uploaders** — they send the sample to a sandbox
 *   or a service, a side effect a reader pressing *Enrich* did not
 *   ask for;
 * - **document transforms** — they turn an attachment into text;
 * - **query builders and validators** — they compile or check a rule.
 *
 * Offered beside passive DNS on the Value Intelligence or the graph, they
 * would read as lookups. So they are left out of every enrichment
 * surface, and — as with `ModuleLocality` — the profile's
 * `enrichment.roles` map may say otherwise, per module, in either
 * direction: an operator who wants `html_to_markdown` offered says
 * `enrichment`, one who wants a shipped lookup kept off says `other`.
 */
class ModuleRole
{
    const ENRICHMENT = 'enrichment';
    const OTHER = 'other';

    /** By each module's exact introspection `name`. */
    const NOT_ENRICHMENT = array(
        // Submitters and uploaders.
        'anyrun_sandbox_submit',
        'assemblyline_submit',
        'cuckoo_submit',
        'joesandbox_submit',
        'lastline_submit',
        'malshare_upload',
        'triage_submit',
        'virustotal_upload',
        'vmray_submit',
        // Document transforms.
        'convert_markdown_to_pdf',
        'docx_enrich',
        'html_to_markdown',
        'jinja_template_rendering',
        'ocr_enrich',
        'ods_enrich',
        'odt_enrich',
        'pdf_enrich',
        'pptx_enrich',
        'qrcode',
        'xlsx_enrich',
        // Query builders and validators.
        'eql',
        'sigma_queries',
        'sigma_syntax_validator',
        'stix2_pattern_syntax_validator',
        'yara_query',
        'yara_syntax_validator',
    );

    /**
     * @param string|null $name The module's `name`, exactly
     * @param array $overrides The profile's `enrichment.roles` map
     * @return bool
     */
    public static function isEnrichment($name, array $overrides = array())
    {
        $key = (string)$name;
        if (isset($overrides[$key])
            && in_array($overrides[$key], array(self::ENRICHMENT, self::OTHER), true)
        ) {
            return $overrides[$key] === self::ENRICHMENT;
        }
        return !in_array($key, self::NOT_ENRICHMENT, true);
    }
}
