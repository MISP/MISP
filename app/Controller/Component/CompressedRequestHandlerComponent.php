<?php
class CompressedRequestHandlerComponent extends Component
{
    // Maximum size of uncompressed data to prevent zip bombs
    const MAX_SIZE = 1024 * 1024 * 100;

    public function startup(Controller $controller)
    {
        $contentEncoding = CakeRequest::header('CONTENT_ENCODING');
        if (!empty($contentEncoding)) {
            if ($contentEncoding === 'br') {
                $controller->request->setInput($this->decodeBrotliEncodedContent($controller));
            } else if ($contentEncoding === 'gzip') {
                $controller->request->setInput($this->decodeGzipEncodedContent($controller));
            } else {
                throw new MethodNotAllowedException("Unsupported content encoding '$contentEncoding'.");
            }
        }
    }

    /**
     * @return array
     */
    public function supportedEncodings()
    {
        $supportedEncodings = [];
        if (function_exists('gzdecode') || function_exists('inflate_init')) {
            $supportedEncodings[] = 'gzip';
        }
        if (function_exists('brotli_uncompress') || function_exists('brotli_uncompress_init')) {
            $supportedEncodings[] = 'br';
        }
        return $supportedEncodings;
    }

    /**
     * @return string
     * @throws Exception
     * @see CakeRequest::_readInput()
     */
    private function decodeGzipEncodedContent(Controller $controller)
    {
        if (function_exists('inflate_init')) {
            // Decompress data on the fly if supported
            $resource = inflate_init(ZLIB_ENCODING_GZIP);
            if ($resource === false) {
                throw new Exception('GZIP incremental uncompress init failed.');
            }
            $uncompressed = '';
            foreach ($this->streamInput() as $data) {
                $uncompressedChunk = inflate_add($resource, $data);
                if ($uncompressedChunk === false) {
                    throw new MethodNotAllowedException('Invalid compressed data.');
                }
                $uncompressed .= $uncompressedChunk;
                if (strlen($uncompressed) > self::MAX_SIZE) {
                    throw new Exception("Uncompressed data are bigger than is limit.");
                }
            }
            $uncompressedChunk = inflate_add($resource, '', ZLIB_FINISH);
            if ($uncompressedChunk === false) {
                throw new MethodNotAllowedException('Invalid compressed data.');
            }
            return $uncompressed . $uncompressedChunk;

        } else if (function_exists('gzdecode')) {
            $decoded = gzdecode($controller->request->input(), self::MAX_SIZE);
            if ($decoded === false) {
                throw new MethodNotAllowedException('Invalid compressed data.');
            }
            if (strlen($decoded) >= self::MAX_SIZE) {
                throw new Exception("Uncompressed data are bigger than is limit.");
            }
            return $decoded;
        } else {
            throw new MethodNotAllowedException("This server doesn't support GZIP compressed requests.");
        }
    }

    /**
     * @param Controller $controller
     * @return string
     * @throws Exception
     * @see CakeRequest::_readInput()
     */
    private function decodeBrotliEncodedContent(Controller $controller)
    {
        if (function_exists('brotli_uncompress_init')) {
            // Decompress data on the fly if supported
            $resource = brotli_uncompress_init();
            if ($resource === false) {
                throw new Exception('Brotli incremental uncompress init failed.');
            }
            $uncompressed = '';
            foreach ($this->streamInput() as $data) {
                $uncompressedChunk = brotli_uncompress_add($resource, $data, BROTLI_PROCESS);
                if ($uncompressedChunk === false) {
                    throw new MethodNotAllowedException('Invalid compressed data.');
                }
                $uncompressed .= $uncompressedChunk;
                if (strlen($uncompressed) > self::MAX_SIZE) {
                    throw new Exception("Uncompressed data are bigger than is limit.");
                }
            }
            $uncompressedChunk = brotli_uncompress_add($resource, '', BROTLI_FINISH);
            if ($uncompressedChunk === false) {
                throw new MethodNotAllowedException('Invalid compressed data.');
            }
            return $uncompressed . $uncompressedChunk;

        } else if (function_exists('brotli_uncompress')) {
            $decoded = brotli_uncompress($controller->request->input(), self::MAX_SIZE);
            if ($decoded === false) {
                throw new MethodNotAllowedException('Invalid compressed data.');
            }
            if (strlen($decoded) >= self::MAX_SIZE) {
                throw new Exception("Uncompressed data are bigger than is limit.");
            }
            return $decoded;
        } else {
            throw new MethodNotAllowedException("This server doesn't support brotli compressed requests.");
        }
    }

    /**
     * @param int $chunkSize
     * @return Generator<string>
     * @throws Exception
     */
    private function streamInput($chunkSize = 8192)
    {
        $fh = fopen('php://input', 'rb');
        if ($fh === false) {
            throw new Exception("Could not open PHP input for reading.");
        }
        while (!feof($fh)) {
            $data = fread($fh, $chunkSize);
            if ($data === false) {
                throw new Exception("Could not read PHP input.");
            }
            yield $data;
        }
        fclose($fh);
    }
}
