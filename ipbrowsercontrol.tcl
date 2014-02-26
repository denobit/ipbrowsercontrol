when ACCESS_SESSION_STARTED {

if {([HTTP::path] equals "/example")}{ 

if {not([class match [IP::client_addr] equals ip_allowed]) or not([class match [string tolower [ACCESS::session data get "session.user.agent"]] contains browsers_allowed]) }{
	ACCESS::respond 200 content {<html><body>Access Denied</body></html>}
	log local0.notice "APM-IRule: IP and Browser Control: [ACCESS::session data get "session.user.clientip"] - [ACCESS::session data get "session.user.agent"]"
	ACCESS::session remove
}
}
}
