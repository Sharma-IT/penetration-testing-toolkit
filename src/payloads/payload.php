<?php
/**
 * Test payload for file upload vulnerability detection
 * For educational and authorised testing purposes only
 */

// Start session for rate limiting
session_start();

// Basic security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Function to sanitise input
function sanitize($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Function to log access attempts
function logAccess($type, $details) {
    $logFile = 'access.log';
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] $type: $details\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}

// File Upload Handler
if (isset($_FILES['file'])) {
    $response = array('success' => false, 'message' => '');
    
    try {
        $targetDir = 'uploads/';
        if (!is_dir($targetDir) && !mkdir($targetDir, 0755, true)) {
            throw new Exception("Upload directory creation failed");
        }
        
        $targetFile = $targetDir . basename($_FILES['file']['name']);
        $fileExtension = strtolower(pathinfo($targetFile, PATHINFO_EXTENSION));
        
        // Log the upload attempt
        logAccess('UPLOAD', "File: {$_FILES['file']['name']}, Size: {$_FILES['file']['size']}");
        
        // Simulate successful upload for testing
        $response['success'] = true;
        $response['message'] = "File processed: " . sanitize($_FILES['file']['name']);
        
    } catch (Exception $e) {
        $response['message'] = "Error: " . $e->getMessage();
        logAccess('ERROR', $e->getMessage());
    }
    
    // Return JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

// Default response for direct access
echo "<!-- PHP Upload Test Payload v1.0 -->";
?>
