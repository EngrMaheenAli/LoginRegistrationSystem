<?php
session_start();
require "model/connection.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Sanitize and validate email
    $useremail = filter_var($_POST["useremail"], FILTER_VALIDATE_EMAIL);
    $userpass = trim($_POST["userpass"]);

    if (!$useremail) {
        echo '<script>alert("Please enter a valid email."); window.location.href = "index.php"; </script>';
        exit();
    }

    // Prepare SQL statement to prevent SQL injection
    $stmt = $con->prepare("SELECT * FROM info WHERE Email = ?");
    if (!$stmt) {
        echo '<script>alert("Something went wrong. Please try again later."); window.location.href = "index.php"; </script>';
        exit();
    }

    $stmt->bind_param("s", $useremail);
    if (!$stmt->execute()) {
        echo '<script>alert("Something went wrong. Please try again later."); window.location.href = "index.php"; </script>';
        exit();
    }

    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();

        // Verify the password
        if (password_verify($userpass, $row['Password'])) {
            // Regenerate session ID for added security
            session_regenerate_id(true);

            $_SESSION['useremail'] = $useremail;
            echo '<script>alert("Login successful! Redirecting..."); window.location.href = "welcome.php";</script>';
            exit();
        } else {
            echo '<script>alert("Invalid email or password."); window.location.href = "index.php"; </script>';
        }
    } else {
        echo '<script>alert("Invalid email or password."); window.location.href = "index.php"; </script>';
    }

    $stmt->close();
}
?>


