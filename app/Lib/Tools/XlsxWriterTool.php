<?php
App::uses('TmpFileTool', 'Tools');

/**
 * Minimal streaming XLSX (OOXML SpreadsheetML) writer.
 *
 * Every cell is written as a string cell, so nothing in the workbook is ever
 * evaluated as a formula. A value Excel would turn into a formula if the cell
 * were edited in place carries the quotePrefix style rather than being
 * rewritten, which is what typing a leading apostrophe in Excel actually
 * stores and leaves the value byte-identical to the source.
 */
class XlsxWriterTool
{
    const MAX_ROWS_PER_SHEET = 1048576;
    const MAX_COLUMNS = 16384;
    const MAX_CELL_LENGTH = 32767;

    const STYLE_DEFAULT = 0;
    const STYLE_QUOTE_PREFIX = 1;

    /** Leading characters Excel and LibreOffice treat as a formula start. */
    const FORMULA_LEADS = ['=', '+', '-', '@', "\t", "\r", "\n"];

    const NS_MAIN = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
    const NS_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
    const NS_PKG_REL = 'http://schemas.openxmlformats.org/package/2006/relationships';
    const NS_CT = 'http://schemas.openxmlformats.org/package/2006/content-types';

    /** @var string */
    private $sheetName;

    /** @var bool */
    private $escapeFormulas;

    /** @var bool */
    private $literalPrefix;

    /** @var int */
    private $maxRowsPerSheet;

    /** @var array|null */
    private $headerRow;

    /** @var array List of ['name' => string, 'path' => string] */
    private $sheets = [];

    /** @var resource|null */
    private $handle;

    /** @var int Rows written to the sheet currently open, header included */
    private $rowsInSheet = 0;

    /** @var int */
    private $truncatedCells = 0;

    /** @var int */
    private $escapedCells = 0;

    /** @var string[] Column reference cache, index 0 => 'A' */
    private $columnNames = [];

    /** @var bool */
    private $finished = false;

    /** @var int Survives the temporary file cleanup finish() performs */
    private $sheetCount = 0;

    /**
     * @param array $options sheetName, escapeFormulas, literalPrefix,
     *                       maxRowsPerSheet (tests only)
     * @throws Exception
     */
    public function __construct(array $options = [])
    {
        if (!class_exists('ZipArchive')) {
            throw new Exception(
                'The XLSX export requires the PHP zip extension (ext-zip), ' .
                'which is not installed on this instance.'
            );
        }
        $this->sheetName = $options['sheetName'] ?? 'MISP';
        $this->escapeFormulas = $options['escapeFormulas'] ?? true;
        $this->literalPrefix = $options['literalPrefix'] ?? false;
        $this->maxRowsPerSheet = $options['maxRowsPerSheet'] ?? self::MAX_ROWS_PER_SHEET;
    }

    /**
     * Row repeated at the top of every sheet the workbook rolls over into.
     *
     * @param array $row
     * @throws Exception
     */
    public function setHeader(array $row)
    {
        if (!empty($this->sheets) || $this->handle !== null) {
            throw new Exception('The header must be set before the first row.');
        }
        $this->headerRow = $row;
    }

    /**
     * @param array $row
     * @throws Exception
     */
    public function addRow(array $row)
    {
        if ($this->finished) {
            throw new Exception('Cannot add rows to a finished workbook.');
        }
        if (count($row) > self::MAX_COLUMNS) {
            throw new Exception(sprintf(
                'A worksheet cannot hold more than %d columns, %d requested.',
                self::MAX_COLUMNS,
                count($row)
            ));
        }
        if ($this->handle === null || $this->rowsInSheet >= $this->maxRowsPerSheet) {
            $this->startSheet();
        }
        $this->writeRow($row);
    }

    /**
     * Closes the workbook and returns it.
     *
     * @return TmpFileTool
     * @throws Exception
     */
    public function finish()
    {
        if ($this->finished) {
            throw new Exception('The workbook is already finished.');
        }
        if ($this->handle === null) {
            $this->startSheet();
        }
        $this->closeSheet();
        $this->finished = true;

        $zipPath = $this->createTempFile('xlsxzip');
        try {
            $this->buildPackage($zipPath);
            $output = new TmpFileTool();
            $output->writeFromFile($zipPath);
            return $output;
        } finally {
            @unlink($zipPath);
            $this->cleanup();
        }
    }

    /**
     * @return int Cells cut down to the Excel per-cell character limit
     */
    public function truncatedCells()
    {
        return $this->truncatedCells;
    }

    /**
     * @return int Cells that needed formula neutralisation
     */
    public function escapedCells()
    {
        return $this->escapedCells;
    }

    /**
     * @return int
     */
    public function sheetCount()
    {
        return $this->sheetCount;
    }

    private function startSheet()
    {
        $this->closeSheet();
        $index = count($this->sheets) + 1;
        $path = $this->createTempFile('xlsxsheet');
        $handle = fopen($path, 'w');
        if ($handle === false) {
            throw new Exception("Could not open temporary worksheet file $path.");
        }
        $this->sheets[] = [
            'name' => $index === 1 ? $this->sheetName : $this->sheetName . ' ' . $index,
            'path' => $path,
        ];
        $this->sheetCount = $index;
        $this->handle = $handle;
        $this->rowsInSheet = 0;
        $this->write(
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<worksheet xmlns="' . self::NS_MAIN . '"><sheetData>'
        );
        if ($this->headerRow !== null) {
            $this->writeRow($this->headerRow);
        }
    }

    private function closeSheet()
    {
        if ($this->handle === null) {
            return;
        }
        $this->write('</sheetData></worksheet>');
        fclose($this->handle);
        $this->handle = null;
    }

    private function writeRow(array $row)
    {
        $rowNumber = $this->rowsInSheet + 1;
        $cells = '';
        $column = 0;
        foreach ($row as $value) {
            $cells .= $this->cell($column, $rowNumber, $value);
            $column++;
        }
        $this->write('<row r="' . $rowNumber . '">' . $cells . '</row>');
        $this->rowsInSheet++;
    }

    /**
     * @param int $column Zero based
     * @param int $rowNumber One based
     * @param mixed $value
     * @return string
     */
    private function cell($column, $rowNumber, $value)
    {
        $reference = $this->columnName($column) . $rowNumber;
        $value = $this->normalise($value);
        if ($value === '') {
            return '<c r="' . $reference . '"/>';
        }
        $style = self::STYLE_DEFAULT;
        if ($this->escapeFormulas && in_array($value[0], self::FORMULA_LEADS, true)) {
            $this->escapedCells++;
            if ($this->literalPrefix) {
                $value = "'" . $value;
            } else {
                $style = self::STYLE_QUOTE_PREFIX;
            }
        }
        $attributes = $style === self::STYLE_DEFAULT ? '' : ' s="' . $style . '"';
        return '<c r="' . $reference . '"' . $attributes . ' t="inlineStr">' .
            '<is><t xml:space="preserve">' . $this->escapeXml($value) . '</t></is></c>';
    }

    /**
     * Makes a value safe to place inside an OOXML part: valid UTF-8, free of
     * the control characters XML 1.0 cannot represent, and within Excel's
     * per-cell character limit.
     *
     * @param mixed $value
     * @return string
     */
    private function normalise($value)
    {
        if ($value === null || $value === false) {
            return '';
        }
        if ($value === true) {
            return '1';
        }
        $value = (string)$value;
        if ($value === '') {
            return '';
        }
        if (!mb_check_encoding($value, 'UTF-8')) {
            $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        }
        $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $value);
        if (mb_strlen($value, 'UTF-8') > self::MAX_CELL_LENGTH) {
            $value = mb_substr($value, 0, self::MAX_CELL_LENGTH - 1, 'UTF-8') . '…';
            $this->truncatedCells++;
        }
        return $value;
    }

    private function escapeXml($value)
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }

    /**
     * @param int $index Zero based
     * @return string
     */
    private function columnName($index)
    {
        if (isset($this->columnNames[$index])) {
            return $this->columnNames[$index];
        }
        $name = '';
        $remaining = $index + 1;
        while ($remaining > 0) {
            $name = chr(65 + (($remaining - 1) % 26)) . $name;
            $remaining = intdiv($remaining - 1, 26);
        }
        $this->columnNames[$index] = $name;
        return $name;
    }

    private function buildPackage($zipPath)
    {
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new Exception("Could not create the XLSX package in $zipPath.");
        }
        $zip->addFromString('[Content_Types].xml', $this->contentTypes());
        $zip->addFromString('_rels/.rels', $this->rootRelationships());
        $zip->addFromString('xl/workbook.xml', $this->workbook());
        $zip->addFromString('xl/_rels/workbook.xml.rels', $this->workbookRelationships());
        $zip->addFromString('xl/styles.xml', $this->styles());
        foreach ($this->sheets as $index => $sheet) {
            $zip->addFile($sheet['path'], 'xl/worksheets/sheet' . ($index + 1) . '.xml');
        }
        if ($zip->close() !== true) {
            throw new Exception('Could not finalise the XLSX package.');
        }
    }

    private function contentTypes()
    {
        $overrides = '';
        foreach (array_keys($this->sheets) as $index) {
            $overrides .= '<Override PartName="/xl/worksheets/sheet' . ($index + 1) .
                '.xml" ContentType="application/vnd.openxmlformats-officedocument' .
                '.spreadsheetml.worksheet+xml"/>';
        }
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<Types xmlns="' . self::NS_CT . '">' .
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' .
            '<Default Extension="xml" ContentType="application/xml"/>' .
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' .
            $overrides .
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' .
            '</Types>';
    }

    private function rootRelationships()
    {
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<Relationships xmlns="' . self::NS_PKG_REL . '">' .
            '<Relationship Id="rId1" Type="' . self::NS_REL . '/officeDocument" Target="xl/workbook.xml"/>' .
            '</Relationships>';
    }

    private function workbook()
    {
        $sheets = '';
        foreach ($this->sheets as $index => $sheet) {
            $sheets .= '<sheet name="' . $this->escapeXml($this->sheetTitle($sheet['name'])) .
                '" sheetId="' . ($index + 1) . '" r:id="rId' . ($index + 1) . '"/>';
        }
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<workbook xmlns="' . self::NS_MAIN . '" xmlns:r="' . self::NS_REL . '">' .
            '<sheets>' . $sheets . '</sheets></workbook>';
    }

    private function workbookRelationships()
    {
        $relationships = '';
        foreach (array_keys($this->sheets) as $index) {
            $relationships .= '<Relationship Id="rId' . ($index + 1) . '" Type="' .
                self::NS_REL . '/worksheet" Target="worksheets/sheet' . ($index + 1) . '.xml"/>';
        }
        $relationships .= '<Relationship Id="rId' . (count($this->sheets) + 1) . '" Type="' .
            self::NS_REL . '/styles" Target="styles.xml"/>';
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<Relationships xmlns="' . self::NS_PKG_REL . '">' . $relationships . '</Relationships>';
    }

    /**
     * Style 1 carries quotePrefix, which is how Excel records "this text was
     * entered with a leading apostrophe" without storing the apostrophe.
     */
    private function styles()
    {
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<styleSheet xmlns="' . self::NS_MAIN . '">' .
            '<fonts count="1"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font></fonts>' .
            '<fills count="2"><fill><patternFill patternType="none"/></fill>' .
            '<fill><patternFill patternType="gray125"/></fill></fills>' .
            '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' .
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' .
            '<cellXfs count="2">' .
            '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' .
            '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" quotePrefix="1"/>' .
            '</cellXfs>' .
            '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' .
            '</styleSheet>';
    }

    /**
     * Excel rejects sheet names over 31 characters or containing : \ / ? * [ ]
     */
    private function sheetTitle($name)
    {
        $name = str_replace([':', '\\', '/', '?', '*', '[', ']'], '_', $name);
        return mb_substr($name, 0, 31, 'UTF-8');
    }

    private function createTempFile($prefix)
    {
        $path = tempnam(sys_get_temp_dir(), $prefix);
        if ($path === false) {
            throw new Exception('Could not create a temporary file for the XLSX export.');
        }
        return $path;
    }

    private function write($content)
    {
        if (fwrite($this->handle, $content) === false) {
            throw new Exception('Could not write to the temporary worksheet file.');
        }
    }

    private function cleanup()
    {
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }
        $this->handle = null;
        foreach ($this->sheets as $sheet) {
            @unlink($sheet['path']);
        }
        $this->sheets = [];
    }

    public function __destruct()
    {
        $this->cleanup();
    }
}
