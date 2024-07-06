
//Plugin wrapper class.
function ConfirmCredential( options )
{
    this.plg = _CreatePlugin( "com.candlelight.confirmcredential.plugins.user.ConfirmCredential", options );  
	this.GetVersion = function() { return parseFloat( this.plg.Send( "GetVersion" ) ); }
	
	//Your method calls go here.
	this.IsScreenLockActive = function() { 
	    return this.plg.Send( "isScreenLockActive" ) === "true";
	}
	
	this.ShowAuthScreen = function( callback, duration ) {
	    this.plg.Send( "showAuthScreen", callback.name, duration || 30 );
	}
}

const confirmCredentialInstance = new ConfirmCredential();
app.IsScreenLockActive = confirmCredentialInstance.IsScreenLockActive.bind(confirmCredentialInstance);
app.ShowAuthScreen = confirmCredentialInstance.ShowAuthScreen.bind(confirmCredentialInstance);
