from tornado.web import *
from hashlib import md5

class DigestAuthMixin(object):
    def H(self, data):
        return md5(data).hexdigest()

    def KD(self, secret, data):
        return self.H(secret + ":" + data)

    def A1(self, auth_pass):
        # If 'algorithm' is "MD5" or unset, A1 is:
        # A1 = unq(username-value) ":" unq(realm-value) ":" passwd

        username = self.params["username"]
        return "%s:%s:%s" % (username, self.realm, auth_pass)

        # Not implemented: if 'algorithm' is 'MD5-Sess', A1 is:
        # A1 = H( unq(username-value) ":" unq(realm-value) ":" passwd )
        #  ":" unq(nonce-value) ":" unq(cnonce-value)

    def A2(self):
        """
        If the "qop" directive's value is "auth" or is unspecified, then A2 is:
            A2 = Method ":" digest-uri-value
        Else,
            A2 = Method ":" digest-uri-value ":" H(entity-body)

        """
        if self.params['qop'] == 'auth' or self.params['qop'] == None or self.params['qop'] == '':
            return self.request.method + ":" + self.request.uri
        elif self.params['qop'] == 'auth-int':
            print "UNSUPPORTED 'qop' METHOD\n"
            #return self.request.method + ":" + self.request.uri + H(self.request.body)
        else:
            print "A2 GOT BAD VALUE FOR 'qop': %s\n" % self.params['qop']

    def response(self, auth_pass):
        if self.params.has_key("qop"):
            return self.KD(self.H(self.A1(auth_pass)),
                           self.params["nonce"]
                           + ":" + self.params["nc"]
                           + ":" + self.params["cnonce"]
                           + ":" + self.params["qop"]
                           + ":" + self.H(self.A2()))
        else:
            return self.KD(self.H(self.A1(auth_pass)), \
                           self.params["nonce"] + ":" + self.H(self.A2()))

    def _parseHeader(self, authheader):
        try:
            n = len("Digest ")
            authheader = authheader[n:].strip()
            items = authheader.split(", ")
            keyvalues = [i.split("=", 1) for i in items]
            keyvalues = [(k.strip(), v.strip().replace('"', '')) for k, v in keyvalues]
            self.params = dict(keyvalues)
        except:
            self.params = []

    def _createNonce(self):
        return md5("%d:%s" % (time.time(), self.realm)).hexdigest()

    def createAuthHeader(self):
        self.set_status(401)
        nonce = self._createNonce()
        self.set_header("WWW-Authenticate", "Digest algorithm=MD5 realm=%s qop=auth nonce=%s" % (self.realm, nonce))
        self.finish()

        return False

    def get_authenticated_user(self, get_creds_callback, realm):
        if not hasattr(self,'realm'):
            self.realm = realm

        try:
            auth = self.request.headers.get('Authorization')
            if auth == None:
                return self.createAuthHeader()
            elif not auth.startswith('Digest '):
                return self.createAuthHeader()
            else:
                self._parseHeader(auth)
                required_params = ['username', 'realm', 'nonce', 'uri', 'response', 'qop', 'nc', 'cnonce']
                for k in required_params:
                    if not self.params.has_key(k):
                        print "REQUIRED PARAM %s MISSING\n" % k
                        return self.createAuthHeader()
                    elif self.params[k] is None or self.params[k] == '':
                        print "REQUIRED PARAM %s IS NONE OR EMPTY\n" % k
                        return self.createAuthHeader()
                    else:
                        continue
                        #print k,":",self.params[k]

            creds = get_creds_callback(self.params['username'])
            if not creds:
                self.send_error(400)
            else:
                expected_response = self.response(creds['auth_password'])
                actual_response = self.params['response']

            if expected_response and actual_response:
                if expected_response == actual_response:
                    self._current_user = self.params['username']
                    print "Digest Auth user '%s' successful for realm '%s'. URI: '%s', IP: '%s'" % (self.params['username'], self.realm, self.request.uri, self.request.remote_ip)
                    return True
                else:
                    self.createAuthHeader()

        except Exception as out:
            print "FELL THROUGH: %s\n" % out
            print "AUTH HEADERS: %s" % auth
            print "SELF.PARAMS: ",self.params,"\n"
            print "CREDS: ", creds
            print "EXPECTED RESPONSE: %s" % expected_response
            print "ACTUAL RESPONSE: %s" % actual_response
            return self.createAuthHeader()


def digest_auth(realm, auth_func):
    """A decorator used to protect methods with HTTP Digest authentication.

    """
    def digest_auth_decorator(func):
        def func_replacement(self, *args, **kwargs):
            if self.get_authenticated_user(auth_func, realm):
                return func(self, *args, **kwargs)
        return func_replacement
    return digest_auth_decorator
