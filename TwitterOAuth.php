<?php

/**
 * TwitterOAuth class file
 * is used to create a connection between Twitter (service),
 * Twitter user (resource) and your Twitter application (consumer), using OAuth 1.0.
 *
 * @author Santiago Carmo <santiagocca@gmail.com>
 * @copyright Copyright &copy; 2012 Santiago Carmo
 * @license http://www.gnu.org/copyleft/fdl.html
 * @version 1
**/

/**
 * ------------------------------------------------------------
 * USAGE1 - requiring a oauth_token and authorization:
 * ------------------------------------------------------------
 *
 * require_once 'TwitterOAuth.php';
 *
 * $params = array('consumer_key'       => 'CONSUMER_KEY', 
 *                 'consumer_secret'    => 'CONSUMER_SECRET',
 *                 'oauth_callback_url' => 'CALLBACK_URL');
 *
 * $twitter_oauth = new TwitterOAuth($params);
 * $twitter_oauth->request_token()->request_autorization();
 *
 * ------------------------------------------------------------
 * USAGE2 - requiring access_token:
 * ------------------------------------------------------------
 * require_once('TwitterOAuth.php');
 * $params = array('consumer_key'    => 'CONSUMER_KEY',
 *                 'consumer_secret' =>  'CONSUMER_SECRET',
 *                 'oauth_token'     => $_GET['oauth_token'],
 *                 'oauth_verifier'  => $_GET['oauth_verifier']);
 * 
 * $twitter_oauth = new TwitterOAuth($params);
 * print_r($twitter_oauth->request_access_token());
 *
**/


class TwitterOAuth {
  const OAUTH_VERSION          = '1.0';
  const OAUTH_SIGNATURE_METHOD = 'HMAC-SHA1';
  const REQUEST_TOKEN_URL      = 'https://api.twitter.com/oauth/request_token';
  const ACCESS_TOKEN_URL       = 'http://api.twitter.com/oauth/access_token';
  const AUTHORIZE_URL          = "http://api.twitter.com/oauth/authorize";        

  public $oauth_timestamp;
  public $consumer_key;  
  public $consumer_secret;  
  public $oauth_verifier;
  public $oauth_callback_url;
  public $oauth_token;
  public $base_string;
  public $composite_key;
  public $request_token_response;
  
  public function __construct($params = array()) {
    $default = array('consumer_key' => '', 'consumer_secret' => '', 'oauth_callback_url' => '', 'oauth_token' => NULL, 'oauth_verifier' => NULL);
    $params  = array_merge($default, $params);
    
    $this->oauth_timestamp    = time();
    $this->consumer_key       = $params['consumer_key'];
    $this->consumer_secret    = $params['consumer_secret'];
    $this->oauth_callback_url = $params['oauth_callback_url'];
    $this->oauth_token        = $params['oauth_token'];
    $this->oauth_verifier     = $params['oauth_verifier'];
  }
  
  private function create_oauth_params() {
    return array('oauth_callback'         => $this->oauth_callback_url,
                 'oauth_consumer_key'     => $this->consumer_key,
                 'oauth_nonce'            => $this->oauth_timestamp,
                 'oauth_signature_method' => self::OAUTH_SIGNATURE_METHOD,
                 'oauth_timestamp'        => $this->oauth_timestamp,
                 'oauth_version'          => self::OAUTH_VERSION);
  }
  
  private function build_base_string($method = 'POST') {
    $raw_encoded  = array();
    $oauth_params = $this->create_oauth_params();
    ksort($oauth_params);

    foreach($oauth_params as $key => $value) { $raw_encoded[] = "{$key}=" . rawurlencode($value); }
    $this->base_string = "{$method}&" . rawurlencode(self::REQUEST_TOKEN_URL) . '&' . rawurlencode(implode('&', $raw_encoded)); 
    return $this;
  }
  
  private function build_base_access_url() {
    $raw_encoded                          = array();
    $this->oauth_params['oauth_token']    = $this->oauth_token;
    $this->oauth_params['oauth_verifier'] = $this->oauth_verifier;

    unset($this->oauth_params['oauth_callback']);
    ksort($this->oauth_params);

    foreach($this->oauth_params as $key => $value) { $raw_encoded[] = "{$key}=" . rawurlencode($value); }
    return implode('&', $raw_encoded);
  }
  
  private function build_authorization_header($oauth_params = NULL) {
    $raw_encoded_string = 'Authorization: OAuth '; 
    $values             = array();
    $oauth_params       = $oauth_params;
    
    foreach($oauth_params as $key => $value) { $values[] = "{$key}=\"" . rawurlencode($value) . "\""; }
    $raw_encoded_string .= implode(', ', $values); 
    return $raw_encoded_string; 
  }
  
  private function get_composite_key() {
    $this->composite_key = rawurlencode($this->consumer_secret) . '&' . rawurlencode($this->oauth_token);
    return $this;
  }
  
  private function generate_oauth_signature() {
    return base64_encode(hash_hmac('sha1', $this->base_string, $this->composite_key, true));
  }
  
  private function curl_request_token() {
      $curl_header  = array($this->build_authorization_header($this->oauth_params), 'Expect:');
      $curl_options = array(CURLOPT_HTTPHEADER     => $curl_header,
                            CURLOPT_HEADER         => false,
                            CURLOPT_URL            => self::REQUEST_TOKEN_URL,
                            CURLOPT_POST           => true,
                            CURLOPT_POSTFIELDS     => null,
                            CURLOPT_RETURNTRANSFER => true,
                            CURLOPT_SSL_VERIFYPEER => false);

      $ch = curl_init();
      curl_setopt_array($ch, $curl_options);
      $response = curl_exec($ch);
      curl_close($ch);
      return $response;
  }
  
  public function request_token() {
    $this->oauth_params                    = $this->create_oauth_params();
    $this->oauth_params['oauth_signature'] = $this->build_base_string()->get_composite_key()->generate_oauth_signature();
    $this->request_token_response          = $this->curl_request_token();
    return $this;
  }
  
  public function request_autorization() {
    $responseArray = array();
    $parts = explode('&', $this->request_token_response);
    foreach($parts as $p){ $p = explode('=', $p); $responseArray[$p[0]] = $p[1]; }
    $this->oauth_token = $responseArray['oauth_token'];
    $this->requests_token_response;
    header("Location: http://api.twitter.com/oauth/authorize?oauth_token={$this->oauth_token}");
  }
  
  public function request_access_token() {
    $this->oauth_params                    = $this->create_oauth_params();
    $this->oauth_params['oauth_signature'] = $this->build_base_string('GET')->get_composite_key()->generate_oauth_signature();
    return file_get_contents(self::ACCESS_TOKEN_URL . '?' . $this->build_base_access_url());
  }
}
?>
