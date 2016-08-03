<?php include('s3.php'); ?>
<a href="<?php echo getSignedUrl($awsAccessKey, $secretKey, $bucket, 'photo1.jpg'); ?>">photo1.jpg</a>
