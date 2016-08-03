<?php
# File: {any-path-you-like}/includes/s3-signed-urls.php
 
# Get the AWS access keys from a non-public server location.
include('awskeys.php');
$bucket = 'babutest1';
 
if(!function_exists('el_crypto_hmacSHA1')){
    /**
    * Calculate the HMAC SHA1 hash of a string.
    *
    * @param string $key The key to hash against
    * @param string $data The data to hash
    * @param int $blocksize Optional blocksize
    * @return string HMAC SHA1
    */
    function el_crypto_hmacSHA1($key, $data, $blocksize = 64) {
        if (strlen($key) > $blocksize) $key = pack('H*', sha1($key));
        $key = str_pad($key, $blocksize, chr(0x00));
        $ipad = str_repeat(chr(0x36), $blocksize);
        $opad = str_repeat(chr(0x5c), $blocksize);
        $hmac = pack( 'H*', sha1(
            ($key ^ $opad) . pack( 'H*', sha1(
                ($key ^ $ipad) . $data
            ))
        ));
        return base64_encode($hmac);
    }
}
 
if(!function_exists('getSignedUrl')){
    /**
    * Create signed URLs to your protected Amazon S3 files.
    *
    * @param string $awsAccessKey Your Amazon S3 access key
    * @param string $secretKey Your Amazon S3 secret key
    * @param string $bucket The bucket (mybucket.s3.amazonaws.com)
    * @param string $objectPath The target file path
    * @param int $expires In minutes
    * @param array $customParams Key value pairs of custom parameters
    * @return string Temporary signed Amazon S3 URL
    * @see http://awsdocs.s3.amazonaws.com/S3/20060301/s3-dg-20060301.pdf
    */
    function getSignedUrl($awsAccessKey, $secretKey, $bucket, $objectPath, $expires = 5, $customParams = array()) {
         
        # Calculate the expire time.
        $expires = time() + intval(floatval($expires) * 60);
         
        # Clean and url-encode the object path.
        $objectPath = str_replace(array('%2F', '%2B'), array('/', '+'), rawurlencode( ltrim($objectPath, '/') ) );
         
        # Create the object path for use in the signature.
        $objectPathForSignature = '/'. $bucket .'/'. $objectPath;
         
        # Create the S3 friendly string to sign.
        $stringToSign = implode("\n", $pieces = array('GET', null, null, $expires, $objectPathForSignature));
         
        # Create the URL frindly string to use.
        $url = 'http://' . $bucket . '.s3.amazonaws.com/' . $objectPath;
         
        # Custom parameters.
        $appendCharacter = '?'; // Default append character.
         
        # Loop through the custom query paramaters (if any) and append them to the string-to-sign, and to the URL strings.
        if(!empty( $customParams )){
                foreach ($customParams as $paramKey => $paramValue) {
                        $stringToSign .= $appendCharacter . $paramKey . '=' . $paramValue;
                        $url .= $appendCharacter . $paramKey . '=' . str_replace(array('%2F', '%2B'), array('/', '+'), rawurlencode( ltrim($paramValue, '/') ) );
                        $appendCharacter = '&';
                }
        }
         
        # Hash the string-to-sign to create the signature.
        $signature = el_crypto_hmacSHA1($secretKey, $stringToSign);
         
        # Append generated AWS parameters to the URL.
        $queries = http_build_query($pieces = array(
            'AWSAccessKeyId' => $awsAccessKey,
            'Expires' => $expires,
            'Signature' => $signature,
        ));
        $url .= $appendCharacter .$queries;
         
        # Return the URL.
        return $url;
         
    }
}
 
?>
