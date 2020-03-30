<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="style.css">
    <title>Amber Cineplex | Profile </title>
</head>
<body>
    <!--Navbar-Starts-->
    
    <nav class="navbar navbar-expand-lg navbar-default fixed-top theme-bg">
        <div class="container">
          <a class="navbar-brand" href="#">Amber Cineplex</a>
          <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNavAltMarkup" aria-controls="navbarNavAltMarkup" aria-expanded="false" aria-h4="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
          </button>
          <div class="collapse navbar-collapse justify-content-end" id="navbarNavAltMarkup">
            <div class="navbar-nav">
              <a class="nav-item nav-link active" href="#">Home <span class="sr-only">(current)</span></a>
              <a class="nav-item nav-link" href="#schedule">Schedule</a>
              <a class="nav-item nav-link" href="#">Pricing</a>
              <a class="nav-item nav-link" href="#booking">Booking</a>
              <a class="nav-item nav-link" href="#upcoming">Upcoming</a>
              <a class="nav-item nav-link" href="#">Contact Us</a>
              <a class="nav-item nav-link" href="#">Profile</a>
              
            </div>
          </div>
        </div>
    </nav>
    <!--NavBar-Ends-->
    <!--Profile Area Start-->
    <div class="container">
        <h1>Edit Profile</h1>
          <hr>
        <div class="row">
          <!-- left column -->
          <div class="col-md-3">
            <div class="text-center">
              <img src="//placehold.it/100" class="avatar img-circle" alt="avatar">
              <h6>Upload a different photo...</h6>
              
              <input type="file" class="form-control">
            </div>
          </div>
          
          <!-- edit form column -->
          <div class="col-md-9 personal-info">
            <div class="alert alert-info alert-dismissable">
              <a class="panel-close close" data-dismiss="alert">×</a> 
              <i class="fa fa-coffee"></i>
              This is an <strong>.alert</strong>. Use this to show important messages to the user.
            </div>
            <h3>Personal info</h3>
            
            <form class="form-horizontal" role="form">
              <div class="form-group">
                <label class="col-lg-3 control-label">First name:</label>
                <div class="col-lg-8">
                  <input class="form-control" type="text" value="Jane">
                </div>
              </div>
              <div class="form-group">
                <label class="col-lg-3 control-label">Last name:</label>
                <div class="col-lg-8">
                  <input class="form-control" type="text" value="Bishop">
                </div>
              </div>
              <div class="form-group">
                <label class="col-lg-3 control-label">Company:</label>
                <div class="col-lg-8">
                  <input class="form-control" type="text" value="">
                </div>
              </div>
              <div class="form-group">
                <label class="col-lg-3 control-label">Email:</label>
                <div class="col-lg-8">
                  <input class="form-control" type="text" value="janesemail@gmail.com">
                </div>
              </div>
              <div class="form-group">
                <label class="col-lg-3 control-label">Time Zone:</label>
                <div class="col-lg-8">
                  <div class="ui-select">
                    <select id="user_time_zone" class="form-control">
                      <option value="Hawaii">(GMT-10:00) Hawaii</option>
                      <option value="Alaska">(GMT-09:00) Alaska</option>
                      <option value="Pacific Time (US &amp; Canada)">(GMT-08:00) Pacific Time (US &amp; Canada)</option>
                      <option value="Arizona">(GMT-07:00) Arizona</option>
                      <option value="Mountain Time (US &amp; Canada)">(GMT-07:00) Mountain Time (US &amp; Canada)</option>
                      <option value="Central Time (US &amp; Canada)" selected="selected">(GMT-06:00) Central Time (US &amp; Canada)</option>
                      <option value="Eastern Time (US &amp; Canada)">(GMT-05:00) Eastern Time (US &amp; Canada)</option>
                      <option value="Indiana (East)">(GMT-05:00) Indiana (East)</option>
                    </select>
                  </div>
                </div>
              </div>
              <div class="form-group">
                <label class="col-md-3 control-label">Username:</label>
                <div class="col-md-8">
                  <input class="form-control" type="text" value="janeuser">
                </div>
              </div>
              <div class="form-group">
                <label class="col-md-3 control-label">Password:</label>
                <div class="col-md-8">
                  <input class="form-control" type="password" value="11111122333">
                </div>
              </div>
              <div class="form-group">
                <label class="col-md-3 control-label">Confirm password:</label>
                <div class="col-md-8">
                  <input class="form-control" type="password" value="11111122333">
                </div>
              </div>
              <div class="form-group">
                <label class="col-md-3 control-label"></label>
                <div class="col-md-8">
                  <input type="button" class="btn btn-primary" value="Save Changes">
                  <span></span>
                  <input type="reset" class="btn btn-default" value="Cancel">
                </div>
              </div>
            </form>
          </div>
      </div>
    </div>
    <hr>
    
    
      <!--Profile Area Ends-->
    




















    <!--JavaScript-->

    <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script>
</body>
</html>