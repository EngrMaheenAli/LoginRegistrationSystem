<?php
session_start();
require "model/connection.php";

// Initialize login attempts
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Sanitize and validate email
    $useremail = filter_var(trim($_POST["useremail"]), FILTER_SANITIZE_EMAIL);
    $userpass = trim($_POST["userpass"]);

    // Check if email and password are provided
    if (empty($useremail) || empty($userpass)) {
        echo '<script>alert("Both email and password are required."); window.location.href = "index.php";</script>';
        exit();
    }

    // Validate email format
    if (!filter_var($useremail, FILTER_VALIDATE_EMAIL)) {
        echo '<script>alert("Please enter a valid email."); window.location.href = "index.php";</script>';
        exit();
    }

    // Check if user has exceeded login attempts (basic brute-force protection)
    if ($_SESSION['login_attempts'] >= 5) {
        echo '<script>alert("Too many login attempts. Please try again after 15 minutes."); window.location.href = "index.php";</script>';
        exit();
    }

    // Prepare SQL statement to prevent SQL injection
    $stmt = $con->prepare("SELECT * FROM info WHERE Email = ?");
    if (!$stmt) {
        echo '<script>alert("Something went wrong. Please try again later."); window.location.href = "index.php";</script>';
        exit();
    }

    $stmt->bind_param("s", $useremail);
    if (!$stmt->execute()) {
        echo '<script>alert("Something went wrong. Please try again later."); window.location.href = "index.php";</script>';
        exit();
    }

    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();

        // Verify the password
        if (password_verify($userpass, $row['Password'])) {
            // Reset login attempts on successful login
            $_SESSION['login_attempts'] = 0;

            // Regenerate session ID for added security
            session_regenerate_id(true);

            $_SESSION['useremail'] = $useremail;
            echo '<script>alert("Login successful! Redirecting..."); window.location.href = "welcome.php";</script>';
            exit();
        } else {
            // Increment login attempts on failed login
            $_SESSION['login_attempts'] += 1;
            echo '<script>alert("Invalid email or password."); window.location.href = "index.php";</script>';
        }
    } else {
        // Increment login attempts if email is not found
        $_SESSION['login_attempts'] += 1;
        echo '<script>alert("Invalid email or password."); window.location.href = "index.php";</script>';
    }

    $stmt->close();
}
?>
