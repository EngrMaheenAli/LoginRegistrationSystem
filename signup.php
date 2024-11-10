<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require "model/connection.php";

$signup = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Sanitize input
    $username = trim(htmlspecialchars($_POST["username"]));
    $useremail = filter_var($_POST["useremail"], FILTER_VALIDATE_EMAIL);
    $userpass = trim($_POST["userpass"]);

    // Validate email
    if (!$useremail) {
        echo '<script>alert("Invalid email format.");</script>';
        exit();
    }

    // Enforce strong password policy
    if (strlen($userpass) < 8 || !preg_match("/[A-Z]/", $userpass) || !preg_match("/[a-z]/", $userpass) || !preg_match("/[0-9]/", $userpass) || !preg_match("/[\W]/", $userpass)) {
        echo '<script>alert("Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character."); window.location.href = "index.php";</script>';
        exit();
    }

    // Hash the password
    $hashedPassword = password_hash($userpass, PASSWORD_DEFAULT);

    // Prepare and execute the SQL query
    $stmt = $con->prepare("INSERT INTO info (Name, Email, Password) VALUES (?, ?, ?)");
    if (!$stmt) {
        echo '<script>alert("Something went wrong. Please try again later."  window.location.href = "index.php"; );</script>';
        exit();
    }

    $stmt->bind_param("sss", $username, $useremail, $hashedPassword);
    if (!$stmt->execute()) {
        echo '<script>alert("Something went wrong. Please try again later."  window.location.href = "index.php"; );</script>';
        exit();
    }

    $signup = true;
    $stmt->close();
}

if ($signup) {
    echo '<script>alert("Hi ' . htmlspecialchars($username) . '! Your account has been created successfully."); window.location.href = "welcome.php";</script>';
    exit();
}
?>
