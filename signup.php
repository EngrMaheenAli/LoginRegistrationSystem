<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require "model/connection.php";

$signup = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Sanitize input to prevent SQL injection and other attacks
    $username = trim(mysqli_real_escape_string($con, $_POST["username"]));
    $useremail = filter_var($_POST["useremail"], FILTER_VALIDATE_EMAIL);
    $userpass = trim($_POST["userpass"]);

    // Hash the password
    $hashedPassword = password_hash($userpass, PASSWORD_DEFAULT);

    // Prepare and execute the SQL query
    $stmt = $con->prepare("INSERT INTO info (Name, Email, Password) VALUES (?, ?, ?)");
    if (!$stmt) {
        die("Prepare statement failed: " . $con->error);
    }

    $stmt->bind_param("sss", $username, $useremail, $hashedPassword);
    if (!$stmt->execute()) {
        die("Execute failed: " . $stmt->error);
    }

    $signup = true;
    $stmt->close();
}

if ($signup) {
    echo "<strong>Hi $username!</strong> Your account has been created successfully.";
    header('Location: welcome.php');
    exit();
}