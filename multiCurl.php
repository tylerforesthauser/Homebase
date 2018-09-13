<?php
// Needs write_log from util and JsonXmlElement - write_log should really be removed.
namespace digitalhigh;
require_once dirname(__FILE__). "/JsonXmlElement.php";
use JsonXmlElement;
class multiCurl
{
    private $urls;
    private $timeout;
    private $files;

	/**
	 * multiCurl constructor.
	 * @param array $urls - Each array item can either be a string consisting of a URL,
	 * or a multidimensional array consisting of [$url, $header, $post=false], where $url is
	 * the URL, $header is an array of header strings, and an optional POST body.
	 * @param int $timeout
	 * @param string | bool $filePath - If specified, try to save data to a file.
	 */
    function __construct(Array $urls, $timeout=10, $filePath=false) {
        $this->urls = $urls;
        $this->timeout = $timeout;
        $this->files = $filePath;
    }

	/**
	 * @return array - Each item in the array will have a key of the URL used, and a value
	 * of the response. If the value is false, it indicates an error occurred and will show
	 * in the log.
	 */
	function process() {
        $urls = $this->urls;
        $timeout = $this->timeout;
        $files = $this->files;
        $mh = curl_multi_init();
        $ch = $res = [];
        foreach($urls as $i => $item) {
            if (is_array($item)) {
                $url = $item[0];
                $header = [$item[1]];
                $post = $item[2] ?? false;
            } else {
                $url = $item;
                $header = $post = false;
                $post = false;
            }
            write_log("URL: $url");
            $ch[$i] = curl_init($url);
            curl_setopt($ch[$i], CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch[$i],CURLOPT_CONNECTTIMEOUT,$timeout);
            curl_setopt($ch[$i],CURLOPT_TIMEOUT,$timeout);

            if ($post) {
				curl_setopt($ch[$i], CURLOPT_POST, count($post));
				curl_setopt($ch[$i], CURLOPT_POSTFIELDS, $post);
			}

            if ($header) {
                //write_log("We have headers: ".json_encode($header));
                curl_setopt($ch[$i],CURLOPT_HTTPHEADER,$header);
            }
            if ($files) {
                curl_setopt($ch[$i], CURLOPT_BINARYTRANSFER, true);
                curl_setopt($ch[$i], CURLOPT_FOLLOWLOCATION, 0);
            }
            curl_multi_add_handle($mh, $ch[$i]);
        }

        // Start performing the request
        do {
            $execReturnValue = curl_multi_exec($mh, $runningHandles);
        } while ($execReturnValue == CURLM_CALL_MULTI_PERFORM);

        // Loop and continue processing the request
        while ($runningHandles && $execReturnValue == CURLM_OK) {
            if (curl_multi_select($mh) != -1) {
                usleep(100);
            }

            do {
                $execReturnValue = curl_multi_exec($mh, $runningHandles);
            } while ($execReturnValue == CURLM_CALL_MULTI_PERFORM);
        }

        // Check for any errors
        if ($execReturnValue != CURLM_OK) {
            write_log("Curl multi read error $execReturnValue!", "ERROR");
        }

        // Extract the content
        foreach($urls as $i => $url) {
            // Check for errors
            $curlError = curl_error($ch[$i]);
            if($curlError == "") {
                $res[$i] = curl_multi_getcontent($ch[$i]);
            } else {
            	$res[$i] = false;
                write_log("Error handling curl '$curlError' for url: $url","ERROR");
            }
            // Remove and close the handle
            curl_multi_remove_handle($mh, $ch[$i]);
            curl_close($ch[$i]);
        }
        // Clean up the curl_multi handle
        curl_multi_close($mh);
        //write_log("Res: ".json_encode($res));
        $results = [];
        foreach ($res as $url => $response) {
            if ($files) {
                $filePath = $files . "/" . rand(1000,10000);
                write_log("Trying to save data from url '$url' to $filePath");
                file_put_contents($filePath, $response);
                $results["$url"] = $filePath;
            } else {
                $data = $json = $xml = false;
                try {
                    $data = json_decode($response, true);
                    if (json_last_error()!==JSON_ERROR_NONE) {
                        write_log("Result for url $url is not JSON.");
                    }
                    $xml = simplexml_load_string($response);
                    if ($xml !== false) {
                        $data = (new JsonXmlElement($response))->asArray();
                        if (!is_array($data)) write_log("Data for url $url is not XML");
                    }
                } catch (\Exception $e) {
                    //write_log("Exception: $e");
                }
                $response = is_array($data) ? $data : $response;
                $results["$url"] = $response;
            }
        }
        unset($mh);
        unset($ch);
        return $results;
    }


    /**
     * Take an array of URL's, and return the first that returns 200, or false if none
     * @return bool | array
     */
    function test() {
        $urls = array_values($this->urls);

        $timeout = $this->timeout;

        $master = curl_multi_init();

        // add additional curl options here
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => $timeout
        ];

        // start the first batch of requests
        foreach ($urls as $url) {
                write_log("Checking $url");
                $ch = curl_init();
                $options[CURLOPT_URL] = $url;
                curl_setopt_array($ch,$options);
                curl_multi_add_handle($master, $ch);
            }

        do {
            while(($execrun = curl_multi_exec($master, $running)) == CURLM_CALL_MULTI_PERFORM);
            if($execrun != CURLM_OK)
                break;
            // a request was just completed -- find out which one
            while($done = curl_multi_info_read($master)) {
                $info = curl_getinfo($done['handle']);
                if ($info['http_code'] == 200)  {
                    curl_multi_close($master);
                    // request successful.  process output using the callback function.
                    $url = $info['url'];
                    write_log("SUCCESS: $url","INFO");
                    return $url;
                }
            }
        } while ($running);

        curl_multi_close($master);
        return false;
    }
}