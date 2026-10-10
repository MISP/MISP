<?php
App::uses('CsvExport', 'Export');
App::uses('TmpFileTool', 'Tools');
App::uses('XlsxWriterTool', 'Tools');

/**
 * Produces the same grid as the CSV export, delivered as an XLSX workbook.
 *
 * Rows are accumulated as CSV in this tool's own temporary file rather than in
 * the stream the driver hands out, and footer() converts that file into the
 * workbook it returns. Every field definition is inherited from CsvExport, so
 * the two formats cannot drift apart.
 */
class XlsxExport extends CsvExport
{
    const SHEET_NAME = 'MISP';

    /** @var TmpFileTool|null */
    private $csv;

    /** @var bool */
    private $hasHeader = false;

    public function header(&$options)
    {
        $this->csv = new TmpFileTool();
        $header = parent::header($options);
        $this->hasHeader = $header !== '';
        $this->csv->write($header);
        return '';
    }

    public function handler($data, $options = array())
    {
        $line = parent::handler($data, $options);
        if ($line !== '' && $line !== null) {
            $this->csv->write($line);
        }
        return '';
    }

    /**
     * @param array $options
     * @return TmpFileTool
     * @throws Exception
     */
    public function footer($options = array())
    {
        if ($this->csv === null) {
            $this->csv = new TmpFileTool();
        }
        $writer = new XlsxWriterTool(array(
            'sheetName' => self::SHEET_NAME,
            'literalPrefix' => !empty($options['filters']['escape_formulas_literal']),
        ));
        $expectHeader = $this->hasHeader;
        // An empty escape character keeps fgetcsv to RFC 4180. With PHP's
        // default backslash escape any value ending in a backslash swallows
        // the rest of the row.
        foreach ($this->csv->intoParsedCsv(',', '"', '') as $row) {
            if (!is_array($row) || (count($row) === 1 && $row[0] === null)) {
                continue;
            }
            if ($expectHeader) {
                $writer->setHeader($row);
                $expectHeader = false;
                continue;
            }
            $writer->addRow($row);
        }
        return $writer->finish();
    }
}
