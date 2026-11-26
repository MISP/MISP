<?php
App::uses('StixExport', 'Export');
App::uses('CakeLog', 'Log');

class Stix1Export extends StixExport
{
    protected $__attributes_limit = 15000;
    protected $__default_version = '1.1.1';
    protected $__sane_versions = array('1.1.1', '1.2');

    /** misp-stix's own default, used when no configured URL qualifies */
    const DEFAULT_NAMESPACE = 'https://misp-project.org';

    /**
     * The rule misp-stix 2026.9.8 applies before framing
     * (misp_stix_converter/tools/stix1_framing.py): an absolute URI -
     * scheme, colon, then URI characters minus the `& " '` an xmlns
     * declaration cannot carry unescaped. Kept in sync by hand.
     */
    const NAMESPACE_REGEX =
        '/^[A-Za-z][A-Za-z0-9+.\-]*:[^\x00-\x20\x7f<>"\'&{}|\\\\^`]+$/D';

    /**
     * Namespace handed to the STIX 1 framing script.
     *
     * MISP.baseurl ships empty and is allowed without a scheme, and
     * misp-stix refuses to frame a namespace that is not an absolute URI.
     * Order: MISP.baseurl, MISP.external_baseurl, then the library default.
     * baseurl stays first on purpose: it has always been the namespace, and
     * the namespace prefixes every id in the package, so moving a configured
     * instance to external_baseurl would change its STIX ids.
     *
     * @param string|null $baseurl MISP.baseurl
     * @param string|null $externalBaseurl MISP.external_baseurl
     * @return string
     */
    public static function framingNamespace($baseurl, $externalBaseurl)
    {
        foreach ([$baseurl, $externalBaseurl] as $candidate) {
            if (is_string($candidate) &&
                preg_match(self::NAMESPACE_REGEX, $candidate)) {
                return $candidate;
            }
        }
        return self::DEFAULT_NAMESPACE;
    }

    protected function __initiate_framing_params()
    {
        $baseurl = Configure::read('MISP.baseurl');
        $namespace = self::framingNamespace(
            $baseurl,
            Configure::read('MISP.external_baseurl')
        );
        if (!empty($baseurl) && $namespace !== $baseurl) {
            CakeLog::warning(
                "STIX 1 export: MISP.baseurl '$baseurl' is not an absolute " .
                "URI, framing under '$namespace' instead."
            );
        }
        return [
            ProcessTool::pythonBin(),
            self::FRAMING_SCRIPT,
            'stix1',
            '-s', $this->__scope,
            '-v', $this->__version,
            '-n', $namespace,
            '-o', Configure::read('MISP.org'),
            '-f', $this->__return_format,
        ];
    }

    protected function __parse_misp_data()
    {
        $command = [
            ProcessTool::pythonBin(),
            self::SCRIPTS_DIR . 'misp2stix.py',
            '-s', $this->__scope,
            '-v', $this->__version,
            '-f', $this->__return_format,
            '-o', Configure::read('MISP.org'),
            '-i',
        ];
        $command = array_merge($command, $this->__filenames);
        try {
            return ProcessTool::execute($command, null, true);
        } catch (ProcessException $e) {
            return $e->stdout();
        }
    }
}
