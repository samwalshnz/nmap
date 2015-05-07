<?php

/**
 * This file is part of the nmap package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */

namespace Nmap;

use Nmap\Util\ProcessExecutor;
use Symfony\Component\Process\ProcessUtils;

/**
 * @author William Durand <william.durand1@gmail.com>
 * @author Aitor García <aitor.falc@gmail.com>
 */
class Nmap {

    private $executor;

    private $outputFile;

    private $executable;

    private $enableOsDetection  = false;

    private $enableServiceInfo  = false;

    private $enableVerbose      = false;

    private $disablePortScan    = false;

    private $disableReverseDNS  = false;

    private $treatHostsAsOnline = false;

    private $enableMacAddresses = false;

    private $serverMacAddress;

    private $serverIpAddress;

    /**
     * Regular expression for matching and validating a MAC address
     *
     * @var string
     */
    private static $valid_mac  = "([0-9A-F]{2}[:-]){5}([0-9A-F]{2})";

    private static $valid_macs = "([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}";

    /**
     * An array of valid MAC address characters
     *
     * @var array
     */
    private static $mac_address_vals = [
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "A", "B", "C", "D", "E", "F"
    ];

    private $timeout = 60;

    /**
     * @return Nmap
     */
    public static function create()
    {
        return new static();
    }

    /**
     * @param ProcessExecutor $executor
     * @param string          $outputFile
     * @param string          $executable
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(ProcessExecutor $executor = null, $outputFile = null, $executable = 'nmap')
    {
        $this->executor   = $executor ?: new ProcessExecutor();
        $this->outputFile = $outputFile ?: sys_get_temp_dir() . '/output.xml';
        $this->executable = $executable;

        $executor = $this->executor;

        // If executor returns anything else than 0 (success exit code), throw an exeption since $executable is not executable.
        if ( $executor->execute($this->executable . ' -v') !== 0 )
        {
            throw new \InvalidArgumentException(sprintf('`%s` is not executable.', $this->executable));
        }
    }

    /**
     * @param array $targets
     * @param array $ports
     *
     * @return Host[]
     */
    public function scan(array $targets, array $ports = [ ])
    {
        $targets = implode(' ', array_map(function ($target)
        {
            return ProcessUtils::escapeArgument($target);
        }, $targets));

        $options = [ ];
        if ( true === $this->enableOsDetection )
        {
            $options[] = '-O';
        }

        if ( true === $this->enableServiceInfo )
        {
            $options[] = '-sV';
        }

        if ( true === $this->enableVerbose )
        {
            $options[] = '-v';
        }

        if ( true === $this->disablePortScan )
        {
            $options[] = '-sn';
        }
        elseif ( ! empty( $ports ) )
        {
            $options[] = '-p ' . implode(',', $ports);
        }

        if ( true === $this->disableReverseDNS )
        {
            $options[] = '-n';
        }

        if ( true == $this->treatHostsAsOnline )
        {
            $options[] = '-Pn';
        }

        if ( true == $this->enableMacAddresses )
        {
            $options[] = '-sP -n';
        }

        $options[] = '-oX';

        $command = sprintf('%s %s %s %s',
                           $this->executable,
                           implode(' ', $options),
                           ProcessUtils::escapeArgument($this->outputFile),
                           $targets
        );

        $this->executor->execute($command, $this->timeout);

        if ( ! file_exists($this->outputFile) )
        {
            throw new \RuntimeException(sprintf('Output file not found ("%s")', $this->outputFile));
        }

        return $this->parseOutputFile($this->outputFile);
    }

    /**
     * @param boolean $enable
     *
     * @return Nmap
     */
    public function enableOsDetection($enable = true)
    {
        $this->enableOsDetection = $enable;

        return $this;
    }

    /**
     * @param boolean $enable
     *
     * @return Nmap
     */
    public function enableServiceInfo($enable = true)
    {
        $this->enableServiceInfo = $enable;

        return $this;
    }

    /**
     * @param boolean $enable
     *
     * @return Nmap
     */
    public function enableVerbose($enable = true)
    {
        $this->enableVerbose = $enable;

        return $this;
    }

    /**
     * @param boolean $disable
     *
     * @return Nmap
     */
    public function disablePortScan($disable = true)
    {
        $this->disablePortScan = $disable;

        return $this;
    }

    /**
     * @param boolean $disable
     *
     * @return Nmap
     */
    public function disableReverseDNS($disable = true)
    {
        $this->disableReverseDNS = $disable;

        return $this;
    }

    /**
     * @param boolean $disable
     *
     * @return Nmap
     */
    public function treatHostsAsOnline($disable = true)
    {
        $this->treatHostsAsOnline = $disable;

        return $this;
    }

    private function parseOutputFile($xmlFile)
    {
        $xml = simplexml_load_file($xmlFile);

        $hosts = [ ];

        foreach ( $xml->host as $rawHost )
        {

            list( $macAddress, $ipAddress ) = $this->parseAddress($rawHost);

            $state = $this->parseState($rawHost);

            /** @var Host $host */
            $host = new Host(
                (string) $ipAddress,
                (string) $state,
                isset( $rawHost->hostnames ) ? $this->parseHostnames($rawHost->hostnames->hostname) : [ ],
                isset( $rawHost->ports ) ? $this->parsePorts($rawHost->ports->port) : [ ],
                (string) $macAddress
            );

            $hosts[] = $host;
        }

        return $hosts;
    }

    private function parseHostnames(\SimpleXMLElement $xmlHostnames)
    {
        $hostnames = [ ];
        foreach ( $xmlHostnames as $hostname )
        {
            $hostnames[] = new Hostname(
                (string) $hostname->attributes()->name,
                (string) $hostname->attributes()->type
            );
        }

        return $hostnames;
    }

    private function parsePorts(\SimpleXMLElement $xmlPorts)
    {
        $ports = [ ];
        foreach ( $xmlPorts as $port )
        {
            $ports[] = new Port(
                (string) $port->attributes()->portid,
                (string) $port->attributes()->protocol,
                (string) $port->state->attributes()->state,
                new Service(
                    (string) $port->service->attributes()->name,
                    (string) $port->service->attributes()->product,
                    (string) $port->service->attributes()->version
                )
            );
        }

        return $ports;
    }

    public function enableMacAddresses($disable = false)
    {
        $this->enableMacAddresses = ! $disable;

        return $this;
    }

    /**
     * @param $host
     * @return array
     */
    private function parseAddress($host)
    {
        foreach ( $host->address as $address )
        {
            $macAddress = null;

            $addressEl = $address->attributes();

            if ( $addressEl->addrtype == 'mac' )
            {
                $macAddress = (string) $addressEl->addr[0];
            }
            else
            {
                $ipAddress = (string) $addressEl->addr;
            }

            if (!$macAddress && $this->getServerIpAddress() == $ipAddress) $macAddress = $this->getServerMacAddress();
        }

        return [ $macAddress, $ipAddress ];
    }

    /**
     * @param $host
     * @return mixed
     */
    private function parseState($host)
    {
        $state = $host->status->attributes()->state;

        return $state;
    }

    /**
     * @return string
     */
    private function getServerIpAddress()
    {
        if ($this->serverIpAddress) return $this->serverIpAddress;

        $this->serverIpAddress = gethostbyname(gethostname());

        return $this->serverIpAddress;
    }

    /**
     * @param string $interface
     * @return bool|string
     */
    private function getServerMacAddress($interface = null)
    {
        if ($this->serverMacAddress) return $this->serverMacAddress;

        if ( ! $interface ) $interface = $this->getInterfaceForIpAddress($this->getServerIpAddress());

        $ifconfig = shell_exec("ifconfig");
        preg_match("/" . self::$valid_macs . "/i", $ifconfig, $macs);


        if ( isset( $macs[0] ) )
        {
            $this->serverMacAddress = trim(strtoupper($macs[0]));

            return $this->serverMacAddress;
        }

        return false;
    }

    /**
     * @param $ipAddress
     * @return string
     */
    private static function getInterfaceForIpAddress($ipAddress)
    {
        $route = "netstat -i";

        exec($route, $output);

        foreach ( $output as $key => $line )
        {
                $hasIpAddressInLine = strpos($line,$ipAddress) !== false;

                if ($hasIpAddressInLine) return substr($line,0,strpos($line, ' '));
        }

        return null;
    }

    /**
     * @return int
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * @param int $timeout seconds
     * @return $this
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;

        return $this;
    }
}
