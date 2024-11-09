<?php
session_start();
require "model/connection.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $useremail = filter_var($_POST["useremail"], FILTER_VALIDATE_EMAIL);
    $userpass = trim($_POST["userpass"]);


    $stmt = $con->prepare("SELECT * FROM info WHERE Email = ?");
    if (!$stmt) {
        die("Prepare statement failed: " . $con->error);
    }

    $stmt->bind_param("s", $useremail);
    if (!$stmt->execute()) {
        die("Execute failed: " . $stmt->error);
    }

    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if (password_verify($userpass, $row['Password'])) {
            $_SESSION['useremail'] = $useremail;
            header("Location: welcome.php");
            exit();
        } else {
            echo "Invalid password";
        }
    } else {
        echo "Invalid email";
    }

    $stmt->close();
}