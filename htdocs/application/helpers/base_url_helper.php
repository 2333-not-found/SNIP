<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * Reverse-proxy aware base_url resolution for SNIP.
 *
 * CodeIgniter's site_url() / base_url() prepend $config['base_url'] to every
 * link, form action, stylesheet, captcha image and redirect.  A single fixed
 * absolute URL therefore cannot serve both an internal address and a public
 * address at the same time.
 *
 * Setting $config['base_url'] to 'auto' (or leaving it empty) lets this helper
 * build the URL from the current request.  The usual reverse-proxy headers are
 * honoured:
 *
 *   X-Forwarded-Proto   http or https
 *   X-Forwarded-Host    public host name (may include a port)
 *   X-Forwarded-Port    public port, used when the host has no port
 *   X-Forwarded-Prefix  public sub-directory, e.g. /snip
 *
 * Example nginx configuration for a public https://example.com/snip/ that
 * proxies to http://127.0.0.1:8075/:
 *
 *   location /snip/ {
 *       proxy_pass http://127.0.0.1:8075/;   # trailing slash strips /snip/
 *       proxy_set_header Host               $http_host;
 *       proxy_set_header X-Forwarded-Proto  $scheme;
 *       proxy_set_header X-Forwarded-Host   $http_host;
 *       proxy_set_header X-Forwarded-Prefix /snip;
 *   }
 */

if ( ! function_exists('snip_resolve_base_url'))
{
    /**
     * Resolve the configured base URL.
     *
     * A fixed value is returned unchanged (apart from normalising the trailing
     * slash).  'auto', an empty string, or a missing value triggers request
     * based detection.
     *
     * @param   array   $config  The SNIP config array ($config in snip.php)
     * @return  string          Base URL with exactly one trailing slash
     */
    function snip_resolve_base_url(array $config)
    {
        $configured = isset($config['base_url']) ? trim((string) $config['base_url']) : '';

        if ($configured !== '' && strcasecmp($configured, 'auto') !== 0)
        {
            return rtrim($configured, '/').'/';
        }

        $trusted_proxies = isset($config['base_url_trusted_proxies'])
            ? trim((string) $config['base_url_trusted_proxies'])
            : '';

        $trust_forwarded = snip_trust_forwarded_headers($trusted_proxies);

        $scheme = snip_request_scheme($trust_forwarded);
        $host   = snip_request_host($trust_forwarded, $scheme);
        $prefix = snip_request_prefix($trust_forwarded, $config);

        return $scheme.'://'.$host.$prefix.'/';
    }
}

if ( ! function_exists('snip_trust_forwarded_headers'))
{
    /**
     * Should X-Forwarded-* headers be trusted for this request?
     *
     * An empty $trusted_proxies value trusts every peer.  That is convenient
     * when SNIP only listens on 127.0.0.1, but it is unsafe if SNIP is directly
     * reachable from untrusted clients.  In that case list the proxy IPs or
     * CIDR ranges, e.g. '127.0.0.1,10.0.0.0/8,172.16.0.0/12'.
     *
     * @param   string  $trusted_proxies  Comma separated IPs / CIDR ranges
     * @return  bool
     */
    function snip_trust_forwarded_headers($trusted_proxies)
    {
        if ($trusted_proxies === '')
        {
            return TRUE;
        }

        $remote = isset($_SERVER['REMOTE_ADDR']) ? trim($_SERVER['REMOTE_ADDR']) : '';
        if ($remote === '')
        {
            return FALSE;
        }

        // Normalise IPv4-mapped IPv6 addresses such as ::ffff:127.0.0.1
        if (stripos($remote, '::ffff:') === 0)
        {
            $ipv4 = substr($remote, 7);
            if (filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
            {
                $remote = $ipv4;
            }
        }

        foreach (explode(',', $trusted_proxies) as $entry)
        {
            $entry = trim($entry);
            if ($entry !== '' && snip_ip_matches($remote, $entry))
            {
                return TRUE;
            }
        }

        return FALSE;
    }
}

if ( ! function_exists('snip_ip_matches'))
{
    /**
     * Check whether an IP address matches an address or CIDR range.
     *
     * @param   string  $ip     IP address, e.g. 127.0.0.1 or ::1
     * @param   string  $rule   IP address or CIDR range, e.g. 10.0.0.0/8
     * @return  bool
     */
    function snip_ip_matches($ip, $rule)
    {
        if (strpos($rule, '/') === FALSE)
        {
            if ($rule === $ip)
            {
                return TRUE;
            }

            $rule_bin = @inet_pton($rule);
            $ip_bin   = @inet_pton($ip);

            return ($rule_bin !== FALSE && $ip_bin !== FALSE && $rule_bin === $ip_bin);
        }

        list($network, $bits) = explode('/', $rule, 2);
        $bits = trim($bits);

        if ($bits === '' || ! ctype_digit($bits))
        {
            return FALSE;
        }

        $bits = (int) $bits;

        $network_bin = @inet_pton(trim($network));
        $ip_bin      = @inet_pton($ip);

        if ($network_bin === FALSE || $ip_bin === FALSE || strlen($network_bin) !== strlen($ip_bin))
        {
            return FALSE;
        }

        $max_bits = strlen($ip_bin) * 8;
        if ($bits < 0 || $bits > $max_bits)
        {
            return FALSE;
        }

        $whole_bytes = intdiv($bits, 8);
        $rest_bits   = $bits % 8;

        if ($whole_bytes > 0 && substr($ip_bin, 0, $whole_bytes) !== substr($network_bin, 0, $whole_bytes))
        {
            return FALSE;
        }

        if ($rest_bits === 0)
        {
            return TRUE;
        }

        $mask = (0xFF << (8 - $rest_bits)) & 0xFF;

        return (ord($ip_bin[$whole_bytes]) & $mask) === (ord($network_bin[$whole_bytes]) & $mask);
    }
}

if ( ! function_exists('snip_request_scheme'))
{
    /**
     * Determine the scheme the client used.
     *
     * @param   bool    $trust_forwarded
     * @return  string  'http' or 'https'
     */
    function snip_request_scheme($trust_forwarded)
    {
        if ($trust_forwarded && ! empty($_SERVER['HTTP_X_FORWARDED_PROTO']))
        {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_PROTO']);
            $proto = strtolower(trim($parts[0]));

            if ($proto === 'http' || $proto === 'https')
            {
                return $proto;
            }
        }

        if ($trust_forwarded && ! empty($_SERVER['HTTP_X_FORWARDED_SSL']))
        {
            if (strtolower(trim($_SERVER['HTTP_X_FORWARDED_SSL'])) === 'on')
            {
                return 'https';
            }
        }

        if ( ! empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off')
        {
            return 'https';
        }

        if ( ! empty($_SERVER['HTTP_FRONT_END_HTTPS']) && strtolower($_SERVER['HTTP_FRONT_END_HTTPS']) !== 'off')
        {
            return 'https';
        }

        if ( ! empty($_SERVER['REQUEST_SCHEME']) && strtolower($_SERVER['REQUEST_SCHEME']) === 'https')
        {
            return 'https';
        }

        if ( ! empty($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443)
        {
            return 'https';
        }

        return 'http';
    }
}

if ( ! function_exists('snip_request_host'))
{
    /**
     * Determine the host (and, when needed, the port) the client used.
     *
     * @param   bool    $trust_forwarded
     * @param   string  $scheme
     * @return  string
     */
    function snip_request_host($trust_forwarded, $scheme)
    {
        $host = '';
        $port = '';

        if ($trust_forwarded)
        {
            if ( ! empty($_SERVER['HTTP_X_FORWARDED_HOST']))
            {
                $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_HOST']);
                $host  = trim($parts[0]);
            }

            if ( ! empty($_SERVER['HTTP_X_FORWARDED_PORT']))
            {
                $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_PORT']);
                $port  = trim($parts[0]);
            }
        }

        if ($host === '')
        {
            if ( ! empty($_SERVER['HTTP_HOST']))
            {
                $host = $_SERVER['HTTP_HOST'];
            }
            elseif ( ! empty($_SERVER['SERVER_NAME']))
            {
                $host = $_SERVER['SERVER_NAME'];
            }
        }

        $host = snip_sanitize_host($host);

        // If the preferred header was unusable, try the server name before
        // falling back to localhost.
        if ($host === '' && ! empty($_SERVER['SERVER_NAME']))
        {
            $host = snip_sanitize_host($_SERVER['SERVER_NAME']);
        }

        if ($host === '')
        {
            $host = 'localhost';
        }

        if ($port !== '' && ctype_digit($port))
        {
            $port = (int) $port;

            if ($port > 0 && $port <= 65535
                && ! snip_host_has_port($host)
                && ! (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)))
            {
                $host .= ':'.$port;
            }
        }

        return $host;
    }
}

if ( ! function_exists('snip_sanitize_host'))
{
    /**
     * Keep only a valid host[:port] value from a Host header.
     *
     * Returning an empty string signals that the header was unusable; this
     * prevents host-header injection from ending up in generated URLs.
     *
     * @param   string  $host
     * @return  string
     */
    function snip_sanitize_host($host)
    {
        $host = trim((string) $host);

        if ($host === '')
        {
            return '';
        }

        // Remove a scheme if a proxy erroneously included one.
        $host = preg_replace('#^[a-z][a-z0-9+.-]*://#i', '', $host);

        // Keep only the authority component.
        $parts = preg_split('~[/?#]~', $host);
        $host  = isset($parts[0]) ? trim($parts[0]) : '';

        // Strip userinfo; it must never be part of a Host value.
        $at = strrpos($host, '@');
        if ($at !== FALSE)
        {
            $host = substr($host, $at + 1);
        }

        if ($host === '')
        {
            return '';
        }

        // Bracketed IPv6 literals, optionally followed by a port.
        if (preg_match('/^\[[0-9a-f:.]+\](?::(\d{1,5}))?$/i', $host, $matches))
        {
            if (isset($matches[1]) && $matches[1] !== ''
                && ((int) $matches[1] < 1 || (int) $matches[1] > 65535))
            {
                return '';
            }

            return $host;
        }

        // Host names and IPv4 literals, optionally followed by a port.
        if (preg_match('/^[a-z0-9._-]+(?::(\d{1,5}))?$/i', $host, $matches))
        {
            if (isset($matches[1]) && $matches[1] !== ''
                && ((int) $matches[1] < 1 || (int) $matches[1] > 65535))
            {
                return '';
            }

            return $host;
        }

        return '';
    }
}

if ( ! function_exists('snip_host_has_port'))
{
    /**
     * Does the host string already contain a port?
     *
     * @param   string  $host
     * @return  bool
     */
    function snip_host_has_port($host)
    {
        if ($host === '')
        {
            return FALSE;
        }

        if ($host[0] === '[')
        {
            return (bool) preg_match('/^\[[^\]]+\]:\d+$/', $host);
        }

        return substr_count($host, ':') === 1;
    }
}

if ( ! function_exists('snip_request_prefix'))
{
    /**
     * Determine the sub-directory the application is published under.
     *
     * Priority:
     *   1. X-Forwarded-Prefix (set by the reverse proxy)
     *   2. $config['base_url_path'] (manual fallback)
     *   3. the directory of SCRIPT_NAME (Apache sub-directory installs)
     *
     * @param   bool    $trust_forwarded
     * @param   array   $config
     * @return  string  '' or '/something' (no trailing slash)
     */
    function snip_request_prefix($trust_forwarded, array $config)
    {
        $prefix = '';

        if ($trust_forwarded && ! empty($_SERVER['HTTP_X_FORWARDED_PREFIX']))
        {
            $parts  = explode(',', $_SERVER['HTTP_X_FORWARDED_PREFIX']);
            $prefix = trim($parts[0]);
        }

        if ($prefix === '' && ! empty($config['base_url_path']))
        {
            $prefix = trim((string) $config['base_url_path']);
        }

        if ($prefix === '' && ! empty($_SERVER['SCRIPT_NAME']))
        {
            $script = str_replace('\\', '/', $_SERVER['SCRIPT_NAME']);
            $dir    = dirname($script);

            // Ignore Windows filesystem paths (SCRIPT_NAME should be a URL
            // path, but do not turn "C:/..." into a URL prefix).
            if (preg_match('#^[A-Za-z]:/#', $dir))
            {
                $dir = '';
            }

            if ($dir !== '.' && $dir !== '/' && $dir !== '')
            {
                $prefix = $dir;
            }
        }

        $prefix = '/'.trim(str_replace('\\', '/', $prefix), '/');

        if ($prefix === '/')
        {
            return '';
        }

        // Reject traversal and characters that are not valid in a URL path.
        // Quotes, angle brackets and whitespace are deliberately excluded so
        // the value is also safe inside HTML attributes and the inline
        // `var base_url = '...'` script.
        if (strpos($prefix, '..') !== FALSE
            || strpos($prefix, '://') !== FALSE
            || ! preg_match('#^/[A-Za-z0-9._~!$&()*+,;=:@%/-]+$#', $prefix))
        {
            return '';
        }

        return $prefix;
    }
}

/* End of file base_url_helper.php */
/* Location: ./application/helpers/base_url_helper.php */
