<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require "model/connection.php";

$signup = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Sanitize input
    $username = trim(htmlspecialchars($_POST["username"]));
    $useremail = filter_var(trim($_POST["useremail"]), FILTER_SANITIZE_EMAIL);
    $userpass = trim($_POST["userpass"]);

    // Check if all fields are filled
    if (empty($username) || empty($useremail) || empty($userpass)) {
        echo '<script>alert("All fields are required."); window.location.href = "index.php";</script>';
        exit();
    }

    // Validate email format
    if (!filter_var($useremail, FILTER_VALIDATE_EMAIL)) {
        echo '<script>alert("Invalid email format."); window.location.href = "index.php";</script>';
        exit();
    }

    // Enforce strong password policy
    if (strlen($userpass) < 8 || 
        !preg_match("/[A-Z]/", $userpass) || 
        !preg_match("/[a-z]/", $userpass) || 
        !preg_match("/[0-9]/", $userpass) || 
        !preg_match("/[\W]/", $userpass)) 
    {
        echo '<script>alert("Password must be at least 8 characters long, and include an uppercase letter, a lowercase letter, a number, and a special character."); window.location.href = "index.php";</script>';
        exit();
    }

    // Check if the email is already registered
    $stmt = $con->prepare("SELECT Email FROM info WHERE Email = ?");
    if (!$stmt) {
        echo '<script>alert("Something went wrong. Please try again later."); window.location.href = "index.php";</script>';
        exit();
    }

    $stmt->bind_param("s", $useremail);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        echo '<script>alert("Email is already registered. Please use a different email."); window.location.href = "index.php";</script>';
        $stmt->close();
        exit();
    }
    $stmt->close();

    // Hash the password
    $hashedPassword = password_hash($userpass, PASSWORD_DEFAULT);

    // Prepare and execute the SQL query to insert user data
    $stmt = $con->prepare("INSERT INTO info (Name, Email, Password) VALUES (?, ?, ?)");
    if (!$stmt) {
        echo '<script>alert("Something went wrong. Please try again later."); window.location.href = "index.php";</script>';
        exit();
    }

    $stmt->bind_param("sss", $username, $useremail, $hashedPassword);
    if (!$stmt->execute()) {
        echo '<script>alert("Something went wrong. Please try again later."); window.location.href = "index.php";</script>';
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
