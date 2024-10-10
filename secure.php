<?php

session_start(); // Start the session

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Define rate limiter configuration
$maxRequests = 5000; // Maximum number of requests
$interval = 60 * 60 * 24; // Time window in seconds (each day)

// Get the user's IP address
$ipAddress = $_SERVER['REMOTE_ADDR'];

// Initialize the rate limiter data if not set
if (!isset($_SESSION['rate_limiter'])) {
    $_SESSION['rate_limiter'] = [];
}

// Initialize user's request count and timestamp
if (!isset($_SESSION['rate_limiter'][$ipAddress])) {
    $_SESSION['rate_limiter'][$ipAddress] = [
        'request_count' => 0,
        'first_request_time' => time()
    ];
}

// Check the time since the first request
$timeSinceFirstRequest = time() - $_SESSION['rate_limiter'][$ipAddress]['first_request_time'];

// Reset the count if the interval has passed
if ($timeSinceFirstRequest > $interval) {
    $_SESSION['rate_limiter'][$ipAddress]['request_count'] = 0;
    $_SESSION['rate_limiter'][$ipAddress]['first_request_time'] = time();
}

$_SESSION['rate_limiter'][$ipAddress]['request_count']++;
// Consume a request
if ($_SESSION['rate_limiter'][$ipAddress]['request_count'] >= $maxRequests) {
    // Rate limit exceeded
    http_response_code(429); // Too Many Requests
    echo json_encode(['error' => 'Rate limit exceeded. Please try again later.']);
    error_log("Rate limit exceeded for IP: " . $ipAddress);
}

// Global variables
$ciphering = "AES-128-CTR";
$encryption_iv = '1234567891011121';
$decryption_iv = '1234567891011121';
$encryption_key = "AhmadSalehHere";
$options = 0;

// Function to encrypt a string
function encrypt_string($input_string) {
    global $ciphering, $encryption_key, $options, $encryption_iv;
    $encryption = openssl_encrypt($input_string, $ciphering, $encryption_key, $options, $encryption_iv);
    return $encryption;
}

// Function to decrypt a string
function decrypt_string($encrypted_string) {
    global $ciphering, $encryption_key, $options, $decryption_iv;

    $decryption = openssl_decrypt($encrypted_string, $ciphering, $encryption_key, $options, $decryption_iv);

    if ($decryption === false) {
        // Handle decryption error
        $error = openssl_error_string();
        error_log("OpenSSL decryption error: $error");
        return null; // or handle the error in a way suitable for your application
    }

    return $decryption;
}

// Encrypt multiple strings at once (batch encryption)
function encrypt_strings_batch($input_strings) {
    $encrypted_strings = [];
    
    foreach ($input_strings as $string) {
        $encrypted = encrypt_string($string);
        if ($encrypted !== false) {
            $encrypted_strings[] = $encrypted;
        } else {
            error_log("Failed to encrypt string: $string");
        }
    }
    
    return $encrypted_strings;
}

// Decrypt multiple strings at once (batch decryption)
function decrypt_strings_batch($encrypted_strings) {
    $decrypted_strings = [];
    
    foreach ($encrypted_strings as $encrypted) {
        $decrypted = decrypt_string($encrypted);
        if ($decrypted !== null) {
            $decrypted_strings[] = $decrypted;
        } else {
            error_log("Failed to decrypt string: $encrypted");
        }
    }
    
    return $decrypted_strings;
}

// Check if a POST request with 'action' parameter is sent
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    // Allow requests only from specific origins
    $allowed_origins = ['https://tulkarem-school.com','https://www.tulkarem-school.com','https://alsfarene-school.com','https://www.alsfarene-school.com','https://alameer-driving.com','https://www.alameer-driving.com','https://maherjohari-d-school.com','https://www.maherjohari-d-school.com','https://al-nasser-school.com','https://www.al-nasser-school.com','https://dwikatschool.com','https://www.dwikatschool.com','https://natsheh-school.com','https://www.natsheh-school.com','https://tareqdarwish.com','https://www.tareqdarwish.com','https://bustami.net','https://www.bustami.net','https://alameer-school.com','https://www.alameer-school.com','https://hajhamad.com','https://www.hajhamad.com','https://aleman-sch.com','https://www.aleman-sch.com','https://bessan-school.com','https://www.bessan-school.com','https://altawfeq-school.com','https://www.altawfeq-school.com','https://test.mekkawe.com','https://www.test.mekkawe.com','https://al-samaqa.com','https://www.al-samaqa.com','https://zakarneh-school.com','https://www.zakarneh-school.com','https://nasseralhroub.com','https://www.nasseralhroub.com','https://mekkawe.com','https://www.mekkawe.com', 'https://al-akhwa.com', 'https://www.al-akhwa.com','https://ethadamer0569880001.com','https://www.ethadamer0569880001.com', 'https://www.tulkarem-driving.com', 'https://tulkarem-driving.com', 'https://mekkawe-com.translate.goog', 'https://www.mekkawe-com.translate.goog', 'https://nasseralhroub-com.translate.goog', 'https://www.nasseralhroub-com.translate.goog'];
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    if (in_array($origin, $allowed_origins)) {
        header("Access-Control-Allow-Origin: $origin");
        header('Access-Control-Allow-Methods: POST');
        header('Access-Control-Allow-Headers: Content-Type');
        
        $action = $_POST['action'];

        // Handle different actions
        switch ($action) {
            case 'encrypt':
                if (isset($_POST['input'])) {
                    $input = $_POST['input'];
                    $encrypted_string = encrypt_string($input);
                    echo json_encode(['encrypted_string' => $encrypted_string]);
                } else {
                    echo json_encode(['error' => 'Missing input parameter']);
                }
                break;

            case 'decrypt':
                if (isset($_POST['encrypted_string'])) {
                    $encrypted_string = $_POST['encrypted_string'];
                    $decrypted_string = decrypt_string($encrypted_string);
                    echo json_encode(['decrypted_string' => $decrypted_string]);
                } else {
                    echo json_encode(['error' => 'Missing encrypted_string parameter']);
                }
                break;
            case 'decrypt_at_once':
                if (isset($_POST['encrypted_strings'])) {
                    $encrypted_strings = json_decode($_POST['encrypted_strings'], true);
                    $decrypted_strings = [];
            
                    foreach ($encrypted_strings as $encrypted_string) {
                        $decrypted_string = decrypt_string($encrypted_string);
                        $decrypted_strings[] = $decrypted_string;
                    }
            
                    echo json_encode(['decrypted_strings' => $decrypted_strings]);
                } else {
                    echo json_encode(['error' => 'Missing encrypted_strings parameter']);
                }
                break;

            default:
                echo json_encode(['error' => 'Invalid action']);
                break;
        }
    } else {
        // Return an error for requests from unauthorized origins
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Unauthorized origin']);
    }
}
?>
