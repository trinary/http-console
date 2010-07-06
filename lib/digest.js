var http = require("http");
var hashlib = require("hashlib");
var sys = require("sys");

var wwwAuthMap = {
  "algorithm" : "algorithm=",
	"realm" : "realm=\"",
	"nonce" : "nonce=\"",
	"qop" : "qop=\"",
	"opaque" : "opaque=\"",
	"stale" : "stale="
};

function DigestClient(client, username, password, expectedRealm){
	var self = this;
	self.client = client;
	self.username = username;
	self.password = password;
	self.expectedRealm = expectedRealm;

	/* FIXME This is bad, should use a random cnonce! */
	self.cnonce = "cdb0e64d1ded02dd";

	/* Initialize qop */
	self.qop = null;
	self.opaque = null;

	/* Have not yet determined realm. */
	self.HA1 = null;

	return self;
}

DigestClient.prototype.request = function(method, path, request_headers){
	var self = this;

  sys.puts("digest request");
	/* If method omitted, assume it was GET. */
  if(typeof(path) != "string"){
    headers = path;
    url = method;
    method = "GET";
  }

	/* If we have a definite HA1 then send authentication header. */
	if(self.HA1){
		var HA2 = (method + ":" + path);
		/* FIXME Handle "auth-int" case! */
		//if(self.qop == "auth" || self.qop == "auth-int"){
		//}

		/* Calculate 8 digit hex nc value. */
		var nc = self.nonceCount.toString(16);
		while(nc.length < 8)
			nc = "0" + nc;

		HA2 = hashlib.md5(HA2);

		/* Calculate middle portion of undigested 'response' */
		var middle = self.nonce;
		if(self.qop == "auth" || self.qop == "auth-int"){
			middle += ":" + nc + ":" + self.cnonce
				+ ":" + self.qop;
		}

		/* Digest the response. */
		var response = self.HA1 + ":" + middle + ":" + HA2;
		response = hashlib.md5(response);

		/* Assemble the header value. */
		var hdrVal = "Digest username=\"" + self.username
			+ "\", realm=\"" + self.realm
			+ "\", nonce=\"" + self.nonce
			+ "\", uri=\"" + path + "\"";

		if(self.qop){
			hdrVal += ", qop=" + self.qop
				+ ", nc=" + nc
				+ ", cnonce=\"" + self.cnonce + '"';
		}

		hdrVal += ", response=\"" + response + '"';
		if(self.opaque)
			hdrVal += ", opaque=\"" + self.opaque + '"';

		request_headers["authorization"] = hdrVal;
	}

	req = self.client.request(method, path, request_headers);

	req.addListener("response", function(response){
		/* If not authorized, then probably need to update nonce. */
		if(401 == response.statusCode){
			var a = response.headers["www-authenticate"];
			if(a){
				/* Update server values. */
        sys.puts("www-auth header found");
				for(v in wwwAuthMap){
					var idx = a.indexOf(wwwAuthMap[v]);
					if(idx != -1){
						idx += wwwAuthMap[v].length;

						var e = (v != "stale") ? a.indexOf('"', idx) : a.indexOf(',', idx);

						/* Correct for the odd ball stale (has no quotes..)
						 * FIXME handle badly formatted string? */
						if(-1 == e){
							if("stale" == v)
								e = a.length;
						}

						self[v] = a.substring(idx, e);
					}
				}
			}
			else{
				/* FIXME Server is not using auth digest? */
        sys.puts("no www-auth header found");
			}

			/* Verify correct realm. */
			if(self.expectedRealm && self.realm != self.expectedRealm){
				/* FIXME realm mismatch! */
			}

			/* If have previous auth info, then try to revalidate. */
			if(self.HA1){
				/* If did not recv stale, then have bad credentials. */
				if(null == self.stale){
					/* FIXME some kind of exception? */
				}
			}
			else{
				/* Initialize HA1. */
				self.HA1 = self.username + ":" + self.realm + ":" + self.password;
				self.HA1 = hashlib.md5(self.HA1);
			}

			/* HACK FIXME Just dropping back to auth! */
			if(self.qop)
				self.qop = "auth";

			/* Start with 0 nonceCount. */
			self.nonceCount = 0;

			/* FIXME HACK Revise response code to 408 to trick user into retrying.
			 * 401 is not appropriate since the credentials ARE correct.
			 * I didn't store the request, so node users will be pissed that
			 * they have to set up their complicated streams again.
			 * Clearly this is not good karma, but I need this working now. */
			response.statusCode = 408;
		}

		/* Increment the nonceCount */
		++self.nonceCount;
	});

	return req;
}

exports.createClient = function(port, host, username, password, expectedRealm){
	var c = http.createClient(port, host);
	return new DigestClient(c, username, password);
}

var CRLF = "\r\n";
var STATUS_CODES = exports.STATUS_CODES = {
  100 : 'Continue',
  101 : 'Switching Protocols',
  102 : 'Processing',                 // RFC 2518, obsoleted by RFC 4918
  200 : 'OK',
  201 : 'Created',
  202 : 'Accepted',
  203 : 'Non-Authoritative Information',
  204 : 'No Content',
  205 : 'Reset Content',
  206 : 'Partial Content',
  207 : 'Multi-Status',               // RFC 4918
  300 : 'Multiple Choices',
  301 : 'Moved Permanently',
  302 : 'Moved Temporarily',
  303 : 'See Other',
  304 : 'Not Modified',
  305 : 'Use Proxy',
  307 : 'Temporary Redirect',
  400 : 'Bad Request',
  401 : 'Unauthorized',
  402 : 'Payment Required',
  403 : 'Forbidden',
  404 : 'Not Found',
  405 : 'Method Not Allowed',
  406 : 'Not Acceptable',
  407 : 'Proxy Authentication Required',
  408 : 'Request Time-out',
  409 : 'Conflict',
  410 : 'Gone',
  411 : 'Length Required',
  412 : 'Precondition Failed',
  413 : 'Request Entity Too Large',
  414 : 'Request-URI Too Large',
  415 : 'Unsupported Media Type',
  416 : 'Requested Range Not Satisfiable',
  417 : 'Expectation Failed',
  418 : 'I\'m a teapot',              // RFC 2324
  422 : 'Unprocessable Entity',       // RFC 4918
  423 : 'Locked',                     // RFC 4918
  424 : 'Failed Dependency',          // RFC 4918
  425 : 'Unordered Collection',       // RFC 4918
  426 : 'Upgrade Required',           // RFC 2817
  500 : 'Internal Server Error',
  501 : 'Not Implemented',
  502 : 'Bad Gateway',
  503 : 'Service Unavailable',
  504 : 'Gateway Time-out',
  505 : 'HTTP Version not supported',
  506 : 'Variant Also Negotiates',    // RFC 2295
  507 : 'Insufficient Storage',       // RFC 4918
  509 : 'Bandwidth Limit Exceeded',
  510 : 'Not Extended'                // RFC 2774
};

var connectionExpression = /Connection/i;
var transferEncodingExpression = /Transfer-Encoding/i;
var closeExpression = /close/i;
var chunkExpression = /chunk/i;
var contentLengthExpression = /Content-Length/i;


