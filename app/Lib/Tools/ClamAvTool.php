<?php

// TODO: Connection timeout
class ClamAvTool
{
    /** @var resource */
    private $socket;

    /** @var string */
    private $connectionString;

    /**
     * @param $connectionString
     */
    public function __construct($connectionString)
    {
        $this->connectionString = $connectionString;
    }

    /**
     * @throws Exception
     */
    protected function connect()
    {
        if (is_resource($this->socket)) {
            return;
        }

        if (strpos($this->connectionString, 'unix://') === 0) {
            $socket = @socket_create(AF_UNIX, SOCK_STREAM, 0);
            if ($socket === false) {
                $this->socketException();
            }
            $path = substr($this->connectionString, 7);
            $hasError = @socket_connect($socket, $path);
            if ($hasError === false) {
                $this->socketException($socket);
            }

        } else {
            if (strpos(':', $this->connectionString) !== false) {
                throw new InvalidArgumentException("Connection string must be in IP:PORT format.");
            }
            list ($address, $port) = explode(':', $this->connectionString);
            $socket = @socket_create(AF_INET, SOCK_STREAM, 0);
            if ($socket === false) {
                $this->socketException();
            }
            $hasError = @socket_connect($socket, $address, $port);
            if ($hasError === false) {
                $this->socketException($socket);
            }
        }

        $this->socket = $socket;
    }

    /**
     * Returns version of ClamAV.
     * @return array
     * @throws Exception
     */
    public function version()
    {
        $this->connect();
        $this->send("zVERSION\0");
        $result = $this->read();
        list($version, $databaseVersion, $databaseDate) = explode("/", $result);
        return array(
            'version' => $version,
            'databaseVersion' => $databaseVersion,
            'databaseDate' => DateTime::createFromFormat('D M d H:i:s Y', $databaseDate),
        );
    }

    /**
     * @param resource $resource
     * @return array
     * @throws Exception
     */
    public function scanResource($resource)
    {
        if (!is_resource($resource)) {
            throw new InvalidArgumentException("Invalid resource");
        }

        $this->connect();
        $this->send("zINSTREAM\0");
        $this->streamResource($resource);
        $result = $this->read();

        list($type, $scanResult) = explode(': ', $result, 2);
        if ($scanResult === 'OK') {
            return array('found' => false);
        } else {
            $pos = strpos($scanResult, 'FOUND');
            return array('found' => true, 'name' => trim(substr($scanResult, 0, $pos)));
        }
    }

    /**
     * @param resource $resource
     * @return int Number of bytes written
     * @throws Exception
     */
    private function streamResource($resource)
    {
        $result = 0;
        while ($chunk = fread($resource, 1024 * 1024)) {
            $size = pack('N', strlen($chunk));
            $result += $this->send($size . $chunk);

        }
        $result += $this->send(pack('N', 0));
        return $result;
    }

    /**
     * @param string $buf
     * @param int $flags
     * @return int
     * @throws Exception
     */
    private function send($buf, $flags = 0)
    {
        $len = strlen($buf);
        if ($len !== socket_send($this->socket, $buf, $len, $flags)) {
            throw new Exception("Not all data send to stream.");
        }
        return $len;
    }

    /**
     * @param int $flags
     * @return string
     */
    private function read($flags = MSG_WAITALL)
    {
        $data = '';
        while (socket_recv($this->socket, $chunk, 8192, $flags)) {
            $data .= $chunk;
        }

        socket_close($this->socket);
        $this->socket = null;

        return rtrim($data);
    }

    /**
     * @param resource|null $socket
     * @throws Exception
     */
    private function socketException($socket = null)
    {
        $code = socket_last_error($socket);
        throw new Exception(socket_strerror($code), $code);
    }
}
