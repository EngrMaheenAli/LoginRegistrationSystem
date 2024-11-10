<?php
$servername = "localhost";
$username = "root";
$password = "";
$database = "lrs_system";

$con = new mysqli($servername, $username, $password, $database);

if ($con->connect_error) {
    error_log("Database connection failed: " . $con->connect_error);
  
    die("Database connection failed. Please try again later.");
}

$con->set_charset("utf8mb4");
?>
