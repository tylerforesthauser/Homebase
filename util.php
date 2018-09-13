<?PHP

require_once dirname(__FILE__) . '/JsonXmlElement.php';

function array_diff_assoc_recursive($array1, $array2)
{
    foreach($array1 as $key => $value)
    {
        if(is_array($value))
        {
            if(!isset($array2[$key]))
            {
                $difference[$key] = $value;
            }
            elseif(!is_array($array2[$key]))
            {
                $difference[$key] = $value;
            }
            else
            {
                $new_diff = array_diff_assoc_recursive($value, $array2[$key]);
                if($new_diff != FALSE)
                {
                    $difference[$key] = $new_diff;
                }
            }
        }
        elseif(!isset($array2[$key]) || $array2[$key] != $value)
        {
            $difference[$key] = $value;
        }
    }
    return !isset($difference) ? 0 : $difference;
}

function array_filter_recursive(array $array, callable $callback = null) {
    $array = is_callable($callback) ? array_filter($array, $callback) : array_filter($array);
    foreach ($array as &$value) {
        if (is_array($value)) {
            $value = call_user_func(__FUNCTION__, $value, $callback);
        }
    }
    return $array;
}

function arrayContains($str, array $arr) {
    //write_log("Function Fired.");
    $result = array_intersect($arr, explode(" ", $str));
    if (count($result) == 1) $result = true;
    if (count($result) == 0) $result = false;
    return $result;
}

function checkUrl($url, $returnError=false) {
	$cert = getCert();
	$url = filter_var($url, FILTER_SANITIZE_URL);
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        write_log("URL $url is not valid.","ERROR");
        return false;
    }

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_CAINFO, $cert);

    $result = curl_exec($ch);
    /* Get the error code. */
    $httpCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $errMsg = curl_error($ch);
    curl_close($ch);

    $codes = array(100 => "Continue", 101 => "Switching Protocols", 102 => "Processing", 200 => "OK", 201 => "Created", 202 => "Accepted", 203 => "Non-Authoritative Information", 204 => "No Content", 205 => "Reset Content", 206 => "Partial Content", 207 => "Multi-Status", 300 => "Multiple Choices", 301 => "Moved Permanently", 302 => "Found", 303 => "See Other", 304 => "Not Modified", 305 => "Use Proxy", 306 => "(Unused)", 307 => "Temporary Redirect", 308 => "Permanent Redirect", 400 => "Bad Request", 401 => "Unauthorized", 402 => "Payment Required", 403 => "Forbidden", 404 => "Not Found", 405 => "Method Not Allowed", 406 => "Not Acceptable", 407 => "Proxy Authentication Required", 408 => "Request Timeout", 409 => "Conflict", 410 => "Gone", 411 => "Length Required", 412 => "Precondition Failed", 413 => "Request Entity Too Large", 414 => "Request-URI Too Long", 415 => "Unsupported Media Type", 416 => "Requested Range Not Satisfiable", 417 => "Expectation Failed", 418 => "I'm a teapot", 419 => "Authentication Timeout", 420 => "Enhance Your Calm", 422 => "Unprocessable Entity", 423 => "Locked", 424 => "Failed Dependency", 424 => "Method Failure", 425 => "Unordered Collection", 426 => "Upgrade Required", 428 => "Precondition Required", 429 => "Too Many Requests", 431 => "Request Header Fields Too Large", 444 => "No Response", 449 => "Retry With", 450 => "Blocked by Windows Parental Controls", 451 => "Unavailable For Legal Reasons", 494 => "Request Header Too Large", 495 => "Cert Error", 496 => "No Cert", 497 => "HTTP to HTTPS", 499 => "Client Closed Request", 500 => "Internal Server Error", 501 => "Not Implemented", 502 => "Bad Gateway", 503 => "Service Unavailable", 504 => "Gateway Timeout", 505 => "HTTP Version Not Supported", 506 => "Variant Also Negotiates", 507 => "Insufficient Storage", 508 => "Loop Detected", 509 => "Bandwidth Limit Exceeded", 510 => "Not Extended", 511 => "Network Authentication Required", 598 => "Network read timeout error", 599 => "Network connect timeout error");
    /* If the document has loaded successfully without any redirection or error */
    if ($httpCode >= 200 && $httpCode < 300) {
        write_log("Connection is valid: " . $url);
        if ($returnError) return [true,$result];
        return $result;
    } else {
        write_log("Connection failed with error code " . $httpCode . ": " . $url, "ERROR");

        $errMsg = (trim($errMsg) ? $errMsg : ($codes[$httpCode] ?? "Unknown Error."));
        write_log("Error message? - $errMsg");
        if ($returnError) return [false,$errMsg];
        return false;
    }
}

function clearSession() {
    write_log("Function fired");
    foreach($_SESSION as $key=>$val) {
        unset($_SESSION[$key]);
    }
    if (!session_started()) session_start();
    if (isset($_SERVER['HTTP_COOKIE'])) {
        write_log("Cookies found, unsetting.");
        $cookies = explode(';', $_SERVER['HTTP_COOKIE']);
        foreach ($cookies as $cookie) {
            $parts = explode('=', $cookie);
            $name = trim($parts[0]);
            write_log("Cookie: " . $name);
            setcookie($name, '', time() - 1000);
            setcookie($name, '', time() - 1000, '/');
        }
    }
    session_start();
    session_unset();
    $has_session = session_status() == PHP_SESSION_ACTIVE;
    if ($has_session) session_destroy();
    session_write_close();
    setcookie(session_name(), '', 0, '/');
    session_regenerate_id(true);
}

function clientHeaders($server=false, $client=false) {
    $client = $client ? $client : findDevice(false, false, 'Client');
    return array_merge(plexHeaders($server),[
        'X-Plex-Target-Client-Identifier' => $client['Id']
    ]);
}

function curlGet($url, $headers = null, $timeout = 4, $validate=true, $decode=false) {
	$cert = ($validate) ? getCert() : false;
	write_log("GET url $url","INFO","curlGet");
    $url = filter_var($url, FILTER_SANITIZE_URL);
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        write_log("URL $url is not valid.","ERROR");
        return false;
    }
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    if ($validate) curl_setopt($ch, CURLOPT_CAINFO, $cert);
    if ($headers !== null) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $result = curl_exec($ch);
    if (!curl_errno($ch)) {
        switch ($http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE)) {
            case 200:
                break;
            default:
                write_log('Unexpected HTTP code: ' . $http_code . ', URL: ' . $url, "ERROR");
                $result = false;
        }
    }
    curl_close($ch);
    if ($result && $decode) {
    	$array = false;
    	try {
    		$array = json_decode($result,true);
    		if ($array) {
    		    //write_log("Curl result(JSON): " . json_encode($array));
		    } else {
    			$array = (new JsonXmlElement($result))->asArray();
    			if (!empty($array)) {
				    //write_log("Curl result(XML): " . json_encode($array));
			    } else {
    				$array = false;
			    }
		    }
    		if (!$array) write_log("Curl result(String): $result");
	    } catch (Exception $e) {

	    }
	    if (is_array($array)) $result = $array;
    }
    return $result;
}

function curlPost($url, $content = false, $JSON = false, $headers = false, $timeOut=3) {
    write_log("POST url $url","INFO","curlPost");
    $url = filter_var($url, FILTER_SANITIZE_URL);
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        write_log("URL $url is not valid.");
        return false;
    }

	$cert = getCert();
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_HEADER, false);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_CAINFO, $cert);
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 4);
    curl_setopt($curl, CURLOPT_TIMEOUT, $timeOut);
    if ($JSON) {
    	$jsonHeader = ["Content-type: application/json"];
	    $headers = is_array($headers) ? array_merge($headers,$jsonHeader) : $jsonHeader;
    }

    if (is_array($headers)) curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
    if ($content) curl_setopt($curl, CURLOPT_POSTFIELDS, $content);

    $response = curl_exec($curl);
    if (!curl_errno($curl)) {
        switch ($http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE)) {
            case 200:
                break;
            default:
                write_log('Unexpected HTTP code: ' . $http_code . ', URL: ' . $url, "ERROR","curlPost");
                $response = false;
        }
    }
    curl_close($curl);
    return $response;
}

function file_build_path(...$segments) {
    return join(DIRECTORY_SEPARATOR, $segments);
}

function getCaller($custom = "foo") {
    $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
    $useNext = false;
    $caller = false;
    $callers = [];
    foreach ($trace as $event) {
        if ($event['function'] !== "write_log" &&
            $event['function'] !== "getCaller" &&
            $event['function'] !== "initialize" &&
            $event['function'] !== "analyzeRequest") array_push($callers,$event['function']);

//        if ($useNext) {
//            if (($event['function'] != 'require') && ($event['function'] != 'include')) {
//                $caller .= "::" . $event['function'];
//                break;
//            }
//        }
//        if (($event['function'] == 'write_log') || ($event['function'] == 'doRequest') || ($event['function'] == $custom)) {
//            $useNext = true;
//            $file = pathinfo($event['file']);
//            $caller = $file['filename'] . "." . $file['extension'];
//        }
    }
    $file = pathinfo($trace[count($trace) - 1]['file'])['filename'];
    $info = $file . "::" . join(":",array_reverse($callers));
    return $info;
}

function getCert() {
	$file = dirname(__FILE__). "/rw/cacert.pem";
	$url = 'https://curl.haxx.se/ca/cacert.pem';
	$current_time = time();
	$expire_time = 56 * 60 * 60;
	if (file_exists($file)) {
		$file_time = filemtime($file);
		if ($current_time - $expire_time < $file_time) {
			return $file;
		}
	} else {
		write_log("Fetching updated cert.");
		$content = curlGet($url,null,5,false);
		if ($content) {
			$content .= '<!-- cached:  ' . time() . '-->';
			file_put_contents($file, $content);
			write_log('Retrieved fresh from ' . $url, "INFO");
			if (file_exists($file)) return $file;
		}
	}
	// If unable to fetch or write cert, use the "default" one in the project root
	$cert = file_build_path(dirname(__FILE__), "cacert.pem");
	return $cert;
}

function hasGzip() {
    return (function_exists('ob_gzhandler') && ini_get('zlib.output_compression'));
}

function headerHtml() {
    $string = "<div id='X-Plex-Data' class='hidden'";
    foreach(plexHeaders() as $key => $value) {
        $string .= " data-$key='$value'";
    }
    $string .="></div>";
    return $string;
}

function headerQuery($headers) {
    $string = "";
    foreach($headers as $key => $val) {
        $string.="&".urlencode($key)."=".urlencode($val);
    }
    return $string;
}

function headerRequestArray($headers) {
    $headerArray = [];
    foreach ($headers as $key => $val) {
        $headerArray[] = "$key:$val";
    }
    return $headerArray;
}

if (!function_exists('http_build_url')) {
    define('HTTP_URL_REPLACE', 1);              // Replace every part of the first URL when there's one of the second URL
    define('HTTP_URL_JOIN_PATH', 2);            // Join relative paths
    define('HTTP_URL_JOIN_QUERY', 4);           // Join query strings
    define('HTTP_URL_STRIP_USER', 8);           // Strip any user authentication information
    define('HTTP_URL_STRIP_PASS', 16);          // Strip any password authentication information
    define('HTTP_URL_STRIP_AUTH', 32);          // Strip any authentication information
    define('HTTP_URL_STRIP_PORT', 64);          // Strip explicit port numbers
    define('HTTP_URL_STRIP_PATH', 128);         // Strip complete path
    define('HTTP_URL_STRIP_QUERY', 256);        // Strip query string
    define('HTTP_URL_STRIP_FRAGMENT', 512);     // Strip any fragments (#identifier)
    define('HTTP_URL_STRIP_ALL', 1024);         // Strip anything but scheme and host
    // Build an URL
    // The parts of the second URL will be merged into the first according to the flags argument.
    //
    // @param   mixed           (Part(s) of) an URL in form of a string or associative array like parse_url() returns
    // @param   mixed           Same as the first argument
    // @param   int             A bitmask of binary or'ed HTTP_URL constants (Optional)HTTP_URL_REPLACE is the default
    // @param   array           If set, it will be filled with the parts of the composed url like parse_url() would return
    function http_build_url($url, $parts = [], $flags = HTTP_URL_REPLACE, &$new_url = false) {
        $keys = [
            'user',
            'pass',
            'port',
            'path',
            'query',
            'fragment'
        ];
        // HTTP_URL_STRIP_ALL becomes all the HTTP_URL_STRIP_Xs
        if ($flags & HTTP_URL_STRIP_ALL) {
            $flags |= HTTP_URL_STRIP_USER;
            $flags |= HTTP_URL_STRIP_PASS;
            $flags |= HTTP_URL_STRIP_PORT;
            $flags |= HTTP_URL_STRIP_PATH;
            $flags |= HTTP_URL_STRIP_QUERY;
            $flags |= HTTP_URL_STRIP_FRAGMENT;
        } // HTTP_URL_STRIP_AUTH becomes HTTP_URL_STRIP_USER and HTTP_URL_STRIP_PASS
        else if ($flags & HTTP_URL_STRIP_AUTH) {
            $flags |= HTTP_URL_STRIP_USER;
            $flags |= HTTP_URL_STRIP_PASS;
        }
        // Parse the original URL
        // - Suggestion by Sayed Ahad Abbas
        //   In case you send a parse_url array as input
        $parse_url = !is_array($url) ? parse_url($url) : $url;
        // Scheme and Host are always replaced
        if (isset($parts['scheme']))
            $parse_url['scheme'] = $parts['scheme'];
        if (isset($parts['host']))
            $parse_url['host'] = $parts['host'];
        // (If applicable) Replace the original URL with it's new parts
        if ($flags & HTTP_URL_REPLACE) {
            foreach ($keys as $key) {
                if (isset($parts[$key]))
                    $parse_url[$key] = $parts[$key];
            }
        } else {
            // Join the original URL path with the new path
            if (isset($parts['path']) && ($flags & HTTP_URL_JOIN_PATH)) {
                if (isset($parse_url['path']))
                    $parse_url['path'] = rtrim(str_replace(basename($parse_url['path']), '', $parse_url['path']), '/') . '/' . ltrim($parts['path'], '/');
                else
                    $parse_url['path'] = $parts['path'];
            }
            // Join the original query string with the new query string
            if (isset($parts['query']) && ($flags & HTTP_URL_JOIN_QUERY)) {
                if (isset($parse_url['query']))
                    $parse_url['query'] .= '&' . $parts['query'];
                else
                    $parse_url['query'] = $parts['query'];
            }
        }
        // Strips all the applicable sections of the URL
        // Note: Scheme and Host are never stripped
        foreach ($keys as $key) {
            if ($flags & (int)constant('HTTP_URL_STRIP_' . strtoupper($key)))
                unset($parse_url[$key]);
        }
        $new_url = $parse_url;
        return
            ((isset($parse_url['scheme'])) ? $parse_url['scheme'] . '://' : '')
            . ((isset($parse_url['user'])) ? $parse_url['user'] . ((isset($parse_url['pass'])) ? ':' . $parse_url['pass'] : '') . '@' : '')
            . ((isset($parse_url['host'])) ? $parse_url['host'] : '')
            . ((isset($parse_url['port'])) ? ':' . $parse_url['port'] : '')
            . ((isset($parse_url['path'])) ? $parse_url['path'] : '')
            . ((isset($parse_url['query'])) ? '?' . $parse_url['query'] : '')
            . ((isset($parse_url['fragment'])) ? '#' . $parse_url['fragment'] : '');
    }
}

function plexHeaders($token=false) {
    $name = "Homebase";
    $deviceId = "923A3BBB-98AF-53CD-8916-D72BE92DA7E4";
    $headers = [
        "X-Plex-Product"=>$name,
        "X-Plex-Version"=>"2.0",
        "X-Plex-Client-Identifier"=>$deviceId,
        "X-Plex-Platform"=>"Web",
        "X-Plex-Platform-Version"=>"2.0",
        "X-Plex-Sync-Version"=>"2",
        "X-Plex-Device"=>$name,
        "X-Plex-Device-Name"=>"Homebase",
        "X-Plex-Device-Screen-Resolution"=>"1920x1080",
        "X-Plex-Provider-Version"=>"1.2",
	    "X-Plex-Language"=>"en"
    ];
    if ($token) $headers["X-Plex-Token"] = $token;
    return $headers;
}

function plexSignIn($token) {
	$url = "https://plex.tv/pins/$token.xml";
	$user = $token = false;
	$headers = headerRequestArray(plexHeaders());
	$result = curlGet($url,$headers);
	$data = $result ? flattenXML(new SimpleXMLElement($result)) : false;
	if ($data) {
		$token = $data['auth_token'] ?? false;
	}

	if ($token) {
		$user = verifyPlexToken($token);
	}
    return $user;
}

function randomToken($length = 32) {
	write_log("Function fired.");
	if (!isset($length) || intval($length) <= 8) {
		$length = 32;
	}
	if (function_exists('openssl_random_pseudo_bytes')) {
		write_log("Generating using pseudo_random.");
		return bin2hex(openssl_random_pseudo_bytes($length));
	}
	// Keep this last, as there appear to be issues with random_bytes and Docker.
	if (function_exists('random_bytes')) {
		write_log("Generating using random_bytes.");
		return bin2hex(random_bytes($length));
	}
	return false;
}

function scriptDefaults() {
	ini_set("log_errors", 1);
	ini_set('max_execution_time', 300);
	error_reporting(E_ERROR);
	$errorLogPath = file_build_path(dirname(__FILE__), 'logs', 'hOMEBASE_error.log.php');
	ini_set("error_log", $errorLogPath);
	date_default_timezone_set((date_default_timezone_get() ? date_default_timezone_get() : "America/Chicago"));
}


function serverProtocol() {
    return (((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443) ? 'https://' : 'http://');
}

function session_started() {
    return session_status() === PHP_SESSION_NONE ? false : true;
}

function timeStamp() {
	return date(DATE_RFC2822, time());
}

function transcodeImage($path, $server, $full=false) {
    if (preg_match("/library/", $path) || preg_match("/resources/", $path)) {
        write_log("Tick");
        $token = $server['Token'];
        $size = $full ? 'width=1920&height=1920' : 'width=600&height=600';
        $serverAddress = $server['Uri'];
        $url = "$serverAddress/photo/:/transcode?$size&minSize=1&url=" . urlencode($path) . "&X-Plex-Token=$token";
	    $url = cacheImage($url);
        if (!preg_match("/https/",$url)) $url = "https://phlexchat.com/imageProxy.php?url=".urlencode($url);
        return $url;
    }
    write_log("Invalid image path, returning generic image.", "WARN");
    $path = 'https://phlexchat.com/img/avatar.png';
    return $path;
}


/**
 * write ini file
 * @param $data - An associative array (Should probably be fetched from read_ini_file)
 * @param $file - The path to the file
 * @return bool - Whether writing was successful or not.
 */
function write_ini_file($data, $file)
{
	if (!file_exists($file)) {
		return false;
	}

	$content = "";
	foreach ($data as $key => $elem) {
		$content .= "[" . $key . "]\n";
		foreach ($elem as $key2 => $elem2) {
			if (is_array($elem2)) {
				for ($i = 0; $i < count($elem2); $i++) {
					$content .= $key2 . "[] = \"" . $elem2[$i] . "\"\n";
				}
			} else if ($elem2 === "") {
				$content .= $key2 . " = \n";
			} else {
				$content .= $key2 . " = \"" . $elem2 . "\"\n";
			}
		}
	}

	if (!$handle = fopen($file, 'w')) {
		return false;
	}

	if (!fwrite($handle, $content)) {
		return false;
	}

	fclose($handle);
	return true;
}


function write_log($text, $level = false, $caller = false, $force=false) {
    $log = file_build_path(dirname(__FILE__), '.', 'logs', "Homebase.log.php");
    $pp = false;
    if ($force && isset($_GET['pollPlayer'])) {
        $pp = true;
        unset($_GET['pollPlayer']);
    }
    if (!file_exists($log)) {
        touch($log);
        chmod($log, 0666);
        $authString = "; <?php die('Access denied'); ?>".PHP_EOL;
        file_put_contents($log,$authString);
    }
    if (filesize($log) > 10485760) {
        $oldLog = file_build_path(dirname(__FILE__),".",'logs',"Homebase.log.php.old");
        if (file_exists($oldLog)) unlink($oldLog);
        rename($log, $oldLog);
        touch($log);
        chmod($log, 0666);
        $authString = "; <?php die('Access denied'); ?>".PHP_EOL;
        file_put_contents($log,$authString);
    }

    $aux =  microtime(true);
	$now = DateTime::createFromFormat('U.u', $aux);
	if (is_bool($now)) $now = DateTime::createFromFormat('U.u', $aux += 0.001);
	$date = $now->format("m-d-Y H:i:s.u");
    $level = $level ? $level : "DEBUG";
    $user = $_SESSION['plexUserName'] ?? false;
    $user = $user ? "[$user] " : "";
    $caller = $caller ? getCaller($caller) : getCaller();

    if ((isset($_GET['pollPlayer']) || isset($_GET['passive'])) || ($text === "") || !file_exists($log)) return;

    $line = "[$date] [$level] ".$user."[$caller] - $text".PHP_EOL;

    if ($pp) $_SESSION['pollPlayer'] = true;
    if (!is_writable($log)) return;
    if (!$handle = fopen($log, 'a+')) return;
    if (fwrite($handle, $line) === FALSE) return;

    fclose($handle);
}

function writeSession($key, $value, $unset = false) {
	if ($unset) {
		unset($_SESSION[$key]);
	} else {
	    $_SESSION[$key] = $value;
    }
}

function writeSessionArray($array, $unset = false) {
	if ($unset) {
		foreach($array as $key=>$value) {
			unset($_SESSION[$key]);
		}
	} else {
		foreach($array as $key=>$value) {
		    if ($key === 'updated' && empty($value)) {

            } else {
                $_SESSION["$key"] = $value;
            }
		}
	}
}
