<?php

const AES_METHOD = 'aes-256-cbc';

function encrypt($message, $key)
{
    if (OPENSSL_VERSION_NUMBER <= 268443727) {
        throw new RuntimeException('OpenSSL Version too old, vulnerability to Heartbleed');
    }

    $ivSize = openssl_cipher_iv_length(AES_METHOD);
    $iv = openssl_random_pseudo_bytes($ivSize);
    $cipherText = openssl_encrypt($message, AES_METHOD, $key, OPENSSL_RAW_DATA, $iv);
    $cipherTextHex = bin2hex($cipherText);
    $ivHex = bin2hex($iv);

    return "$ivHex:$cipherTextHex";
}

function decrypt($ciphered, $key)
{
    $data = explode(":", $ciphered);
    $iv = hex2bin($data[0]);
    $cipherText = hex2bin($data[1]);

    return openssl_decrypt($cipherText, AES_METHOD, $key, OPENSSL_RAW_DATA, $iv);
}
