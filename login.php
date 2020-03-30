<?php
// Initialize the session
session_start();
include "includes/config.php";
 
// Check if the user is already logged in, if yes then redirect him to welcome page

/*if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === false){
    header("location: welcome.php");
    exit;
}*/

$username = $password = "";
$username_err = $password_err = "";

//for sign in
if (!empty($_POST['signin'])) {
    
    
    // Processing form data when form is submitted
    if($_SERVER["REQUEST_METHOD"] == "POST"){
    
        // Check if username is empty
        if(empty(trim($_POST["username"]))){
            $username_err = "Please enter username.";
        } else{
            $username = trim($_POST["username"]);
        }
        
        // Check if password is empty
        if(empty(trim($_POST["password"]))){
            $password_err = "Please enter your password.";
        } else{
            $password = trim($_POST["password"]);
        }
        
        // Validate credentials
        if(empty($username_err) && empty($password_err)){
            // Prepare a select statement
            $sql = "SELECT id, username, password FROM users WHERE username = ?";
            
            if($stmt = mysqli_prepare($conn, $sql)){
                // Bind variables to the prepared statement as parameters
                mysqli_stmt_bind_param($stmt, "s", $param_username);
                
                // Set parameters
                $param_username = $username;
                
                // Attempt to execute the prepared statement
                if(mysqli_stmt_execute($stmt)){
                    // Store result
                    mysqli_stmt_store_result($stmt);
                    
                    // Check if username exists, if yes then verify password
                    if(mysqli_stmt_num_rows($stmt) == 1){                    
                        // Bind result variables
                        mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                        if(mysqli_stmt_fetch($stmt)){
                            if(password_verify($password, $hashed_password)){
                                // Password is correct, so start a new session
                                session_start();
                                
                                // Store data in session variables
                                $_SESSION["loggedin"] = true;
                                $_SESSION["id"] = $id;
                                $_SESSION["username"] = $username;                            
                                
                                // Redirect user to welcome page
                                header("location: welcome.php");
                            } else{
                                // Display an error message if password is not valid
                                $password_err = "The password you entered was not valid.";
                            }
                        }
                    } else{
                        // Display an error message if username doesn't exist
                        $username_err = "No account found with that username.";
                    }
                } else{
                    echo "Oops! Something went wrong. Please try again later.";
                }

                // Close statement
                mysqli_stmt_close($stmt);
            }
        }
        
        // Close connection
        mysqli_close($conn);
    }
 }
 


 $reg_username = $reg_password = $confirm_password = "";
 $reg_username_err = $reg_password_err = $confirm_password_err = "";




 //for sign up
 if (!empty($_POST['signup'])) {
        // Define variables and initialize with empty values
   
    
    // Processing form data when form is submitted
    if($_SERVER["REQUEST_METHOD"] == "POST"){
    
        // Validate username
        if(empty(trim($_POST["reg_username"]))){
            $reg_username_err = "Please enter a username.";
        } else{
            // Prepare a select statement
            $sql = "SELECT id FROM users WHERE username = ?";
            
            if($stmt = mysqli_prepare($conn, $sql)){
                // Bind variables to the prepared statement as parameters
                mysqli_stmt_bind_param($stmt, "s", $param_username);
                
                // Set parameters
                $param_username = trim($_POST["reg_username"]);
                
                // Attempt to execute the prepared statement
                if(mysqli_stmt_execute($stmt)){
                    /* store result */
                    mysqli_stmt_store_result($stmt);
                    
                    if(mysqli_stmt_num_rows($stmt) == 1){
                        $reg_username_err = "This username is already taken.";
                    } else{
                        $reg_username = trim($_POST["reg_username"]);
                    }
                } else{
                    echo "Oops! Something went wrong. Please try again later.";
                }

                // Close statement
                mysqli_stmt_close($stmt);
            }
        }
        
        // Validate password
        if(empty(trim($_POST["reg_password"]))){
            $reg_password_err = "Please enter a password.";     
        } elseif(strlen(trim($_POST["reg_password"])) < 6){
            $reg_password_err = "Password must have atleast 6 characters.";
        } else{
            $reg_password = trim($_POST["reg_password"]);
        }
        
        // Validate confirm password
        if(empty(trim($_POST["confirm_password"]))){
            $confirm_password_err = "Please confirm password.";     
        } else{
            $confirm_password = trim($_POST["reg_confirm_password"]);
            if(empty($reg_password_err) && ($reg_password != $confirm_password)){
                $confirm_password_err = "Password did not match.";
            }
        }
        
        // Check input errors before inserting in database
        if(empty($reg_username_err) && empty($reg_password_err) && empty($confirm_password_err)){
            
            // Prepare an insert statement
            $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
            
            if($stmt = mysqli_prepare($conn, $sql)){
                // Bind variables to the prepared statement as parameters
                mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
                
                // Set parameters
                $param_username = $reg_username;
                $param_password = password_hash($reg_password, PASSWORD_DEFAULT); // Creates a password hash
                
                // Attempt to execute the prepared statement
                if(mysqli_stmt_execute($stmt)){
                    // Redirect to login page
                    header("location: login.php");
                } else{
                    echo "Something went wrong. Please try again later.";
                }

                // Close statement
                mysqli_stmt_close($stmt);
            }
        }
        
        // Close connection
        mysqli_close($conn);
    }
 }
 
// Include config file
//require_once "config.php";
 






// Define variables and initialize with empty values

?>




<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="login.css">
    
    <title>Amber Cineplex | Log In</title>
</head>
<body >
        
    <div class="container" id="container">
        <div class="form-container sign-up-container">
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                <h1>Create Account</h1>
                
                <input name="reg_username" type="text" placeholder="Username" value="<?php echo $reg_username; ?>"/>
                <span class="help-block"><?php echo $reg_username_err; ?></span>
                <input name="reg_password" type="password" placeholder="password" value="<?php echo $reg_password; ?>" />
                <span class="help-block"><?php echo $reg_password_err; ?></span>
                <input name="reg_confirmPassword" type="password" placeholder="Confirm Password" value="<?php echo $confirm_password; ?>" />
                <span class="help-block"><?php echo $confirm_password_err; ?></span>
                <input type="submit" name='signup' >Sign Up</input>
            </form>
        </div>


        <div class="form-container sign-in-container">
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                    <h1>Sign in</h1>
                    
                    <input type="text" name="username" placeholder="Username" value="<?php echo $username; ?>" />
                    <span class="help-block"><?php echo $username_err; ?></span>
                    <input type="password" name="password" placeholder="Password" />
                    <span class="help-block"><?php echo $password_err; ?></span>
                    <a href="#">Forgot your password?</a>
                    <input type="submit" name='signin'>Sign In</input>
                </div>

            </form>
        </div>
        <div class="overlay-container">
            <div class="overlay">
                <div class="overlay-panel overlay-left">
                    <h1>Welcome Back!</h1>
                    <p>To keep connected with us please login with your personal info</p>
                    <button class="ghost" id="signIn">Sign In</button>
                </div>
                <div class="overlay-panel overlay-right">
                    <h1>Hello, Friend!</h1>
                    <p>Enter your personal details and start journey with us</p>
                    <button class="ghost" id="signUp">Sign Up</button>
                </div>
            </div>
        </div>
    </div>

    <footer>
        <small>©2020. Amber Cineplex | Dhaka, Bangladesh</small>
    </footer>



    <script src="login.js"></script>
</body>
</html>