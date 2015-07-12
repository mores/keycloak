package org.keycloak.services.managers;

import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.ClientConnection;
import org.keycloak.RSATokenVerifier;
import org.keycloak.VerificationException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.UserConsentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredCredentialModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserCredentialValueModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserModel.RequiredAction;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.Urls;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.Time;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import java.net.URI;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Stateless object that manages authentication
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class AuthenticationManager {
    protected static Logger logger = Logger.getLogger(AuthenticationManager.class);
    public static final String FORM_USERNAME = "username";
    // used for auth login
    public static final String KEYCLOAK_IDENTITY_COOKIE = "KEYCLOAK_IDENTITY";
    // used solely to determine is user is logged in
    public static final String KEYCLOAK_SESSION_COOKIE = "KEYCLOAK_SESSION";
    public static final String KEYCLOAK_REMEMBER_ME = "KEYCLOAK_REMEMBER_ME";
    public static final String KEYCLOAK_LOGOUT_PROTOCOL = "KEYCLOAK_LOGOUT_PROTOCOL";

    protected BruteForceProtector protector;

    public AuthenticationManager() {
    }

    public AuthenticationManager(BruteForceProtector protector) {
        this.protector = protector;
    }

    public BruteForceProtector getProtector() {
        return protector;
    }

    public static boolean isSessionValid(RealmModel realm, UserSessionModel userSession) {
        if (userSession == null) {
            logger.debug("No user session");
            return false;
        }
        int currentTime = Time.currentTime();
        int max = userSession.getStarted() + realm.getSsoSessionMaxLifespan();
        return userSession != null && userSession.getLastSessionRefresh() + realm.getSsoSessionIdleTimeout() > currentTime && max > currentTime;
    }

    public static void expireUserSessionCookie(KeycloakSession session, UserSessionModel userSession, RealmModel realm, UriInfo uriInfo, HttpHeaders headers, ClientConnection connection) {
        try {
            // check to see if any identity cookie is set with the same session and expire it if necessary
            Cookie cookie = headers.getCookies().get(KEYCLOAK_IDENTITY_COOKIE);
            if (cookie == null) return;
            String tokenString = cookie.getValue();
            AccessToken token = RSATokenVerifier.verifyToken(tokenString, realm.getPublicKey(), Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName()), false);
            UserSessionModel cookieSession = session.sessions().getUserSession(realm, token.getSessionState());
            if (cookieSession == null || !cookieSession.getId().equals(userSession.getId())) return;
            expireIdentityCookie(realm, uriInfo, connection);
            expireRememberMeCookie(realm, uriInfo, connection);
        } catch (Exception e) {
        }

    }

    /**
     * Do not logout broker
     *
     * @param session
     * @param realm
     * @param userSession
     * @param uriInfo
     * @param connection
     * @param headers
     */
    public static void backchannelLogout(KeycloakSession session, RealmModel realm,
                                         UserSessionModel userSession, UriInfo uriInfo,
                                         ClientConnection connection, HttpHeaders headers,
                                         boolean logoutBroker) {
        if (userSession == null) return;
        UserModel user = userSession.getUser();
        userSession.setState(UserSessionModel.State.LOGGING_OUT);

        logger.debugv("Logging out: {0} ({1})", user.getUsername(), userSession.getId());
        expireUserSessionCookie(session, userSession, realm, uriInfo, headers, connection);

        for (ClientSessionModel clientSession : userSession.getClientSessions()) {
            backchannelLogoutClientSession(session, realm, clientSession, userSession, uriInfo, headers);
        }
        if (logoutBroker) {
            String brokerId = userSession.getNote(IdentityBrokerService.BROKER_PROVIDER_ID);
            if (brokerId != null) {
                IdentityProvider identityProvider = IdentityBrokerService.getIdentityProvider(session, realm, brokerId);
                try {
                    identityProvider.backchannelLogout(userSession, uriInfo, realm);
                } catch (Exception e) {
                }
            }
        }
        userSession.setState(UserSessionModel.State.LOGGED_OUT);
        session.sessions().removeUserSession(realm, userSession);
    }

    public static void backchannelLogoutClientSession(KeycloakSession session, RealmModel realm, ClientSessionModel clientSession, UserSessionModel userSession, UriInfo uriInfo, HttpHeaders headers) {
        ClientModel client = clientSession.getClient();
        if (client instanceof ClientModel && !client.isFrontchannelLogout() && clientSession.getAction() != ClientSessionModel.Action.LOGGED_OUT) {
            String authMethod = clientSession.getAuthMethod();
            if (authMethod == null) return; // must be a keycloak service like account
            LoginProtocol protocol = session.getProvider(LoginProtocol.class, authMethod);
            protocol.setRealm(realm)
                    .setHttpHeaders(headers)
                    .setUriInfo(uriInfo);
            protocol.backchannelLogout(userSession, clientSession);
            clientSession.setAction(ClientSessionModel.Action.LOGGED_OUT);
        }

    }

    // Logout all clientSessions of this user and client
    public static void backchannelUserFromClient(KeycloakSession session, RealmModel realm, UserModel user, ClientModel client, UriInfo uriInfo, HttpHeaders headers) {
        String clientId = client.getId();

        List<UserSessionModel> userSessions = session.sessions().getUserSessions(realm, user);
        for (UserSessionModel userSession : userSessions) {
            List<ClientSessionModel> clientSessions = userSession.getClientSessions();
            for (ClientSessionModel clientSession : clientSessions) {
                if (clientSession.getClient().getId().equals(clientId)) {
                    AuthenticationManager.backchannelLogoutClientSession(session, realm, clientSession, userSession, uriInfo, headers);
                    TokenManager.dettachClientSession(session.sessions(), realm, clientSession);
                }
            }
        }
    }

    public static Response browserLogout(KeycloakSession session, RealmModel realm, UserSessionModel userSession, UriInfo uriInfo, ClientConnection connection, HttpHeaders headers) {
        if (userSession == null) return null;
        UserModel user = userSession.getUser();

        logger.debugv("Logging out: {0} ({1})", user.getUsername(), userSession.getId());
        if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
            userSession.setState(UserSessionModel.State.LOGGING_OUT);
        }
        List<ClientSessionModel> redirectClients = new LinkedList<ClientSessionModel>();
        for (ClientSessionModel clientSession : userSession.getClientSessions()) {
            ClientModel client = clientSession.getClient();
            if (clientSession.getAction() == ClientSessionModel.Action.LOGGED_OUT) continue;
            if (client.isFrontchannelLogout()) {
                String authMethod = clientSession.getAuthMethod();
                if (authMethod == null) continue; // must be a keycloak service like account
                redirectClients.add(clientSession);
                continue;
            }
            if (client instanceof ClientModel && !client.isFrontchannelLogout()) {
                String authMethod = clientSession.getAuthMethod();
                if (authMethod == null) continue; // must be a keycloak service like account
                LoginProtocol protocol = session.getProvider(LoginProtocol.class, authMethod);
                protocol.setRealm(realm)
                        .setHttpHeaders(headers)
                        .setUriInfo(uriInfo);
                try {
                    logger.debugv("backchannel logout to: {0}", client.getClientId());
                    protocol.backchannelLogout(userSession, clientSession);
                    clientSession.setAction(ClientSessionModel.Action.LOGGED_OUT);
                } catch (Exception e) {
                    logger.warn("Failed to logout client, continuing", e);
                }
            }
        }

        for (ClientSessionModel nextRedirectClient : redirectClients) {
            String authMethod = nextRedirectClient.getAuthMethod();
            LoginProtocol protocol = session.getProvider(LoginProtocol.class, authMethod);
            protocol.setRealm(realm)
                    .setHttpHeaders(headers)
                    .setUriInfo(uriInfo);
            // setting this to logged out cuz I"m not sure protocols can always verify that the client was logged out or not
            nextRedirectClient.setAction(ClientSessionModel.Action.LOGGED_OUT);
            try {
                logger.debugv("frontchannel logout to: {0}", nextRedirectClient.getClient().getClientId());
                Response response = protocol.frontchannelLogout(userSession, nextRedirectClient);
                if (response != null) {
                    logger.debug("returning frontchannel logout request to client");
                    return response;
                }
            } catch (Exception e) {
                logger.warn("Failed to logout client, continuing", e);
            }

        }
        String brokerId = userSession.getNote(IdentityBrokerService.BROKER_PROVIDER_ID);
        if (brokerId != null) {
            IdentityProvider identityProvider = IdentityBrokerService.getIdentityProvider(session, realm, brokerId);
            Response response = identityProvider.keycloakInitiatedBrowserLogout(userSession, uriInfo, realm);
            if (response != null) return response;
        }
        return finishBrowserLogout(session, realm, userSession, uriInfo, connection, headers);
    }

    public static Response finishBrowserLogout(KeycloakSession session, RealmModel realm, UserSessionModel userSession, UriInfo uriInfo, ClientConnection connection, HttpHeaders headers) {
        expireIdentityCookie(realm, uriInfo, connection);
        expireRememberMeCookie(realm, uriInfo, connection);
        userSession.setState(UserSessionModel.State.LOGGED_OUT);
        String method = userSession.getNote(KEYCLOAK_LOGOUT_PROTOCOL);
        EventBuilder event = new EventBuilder(realm, session, connection);
        LoginProtocol protocol = session.getProvider(LoginProtocol.class, method);
        protocol.setRealm(realm)
                .setHttpHeaders(headers)
                .setUriInfo(uriInfo)
                .setEventBuilder(event);
        Response response = protocol.finishLogout(userSession);
        session.sessions().removeUserSession(realm, userSession);
        return response;
    }


    public static AccessToken createIdentityToken(RealmModel realm, UserModel user, UserSessionModel session, String issuer) {
        AccessToken token = new AccessToken();
        token.id(KeycloakModelUtils.generateId());
        token.issuedNow();
        token.subject(user.getId());
        token.issuer(issuer);
        if (session != null) {
            token.setSessionState(session.getId());
        }
        if (realm.getSsoSessionMaxLifespan() > 0) {
            token.expiration(Time.currentTime() + realm.getSsoSessionMaxLifespan());
        }
        return token;
    }

    public static void createLoginCookie(RealmModel realm, UserModel user, UserSessionModel session, UriInfo uriInfo, ClientConnection connection) {
        String cookiePath = getIdentityCookiePath(realm, uriInfo);
        String issuer = Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName());
        AccessToken identityToken = createIdentityToken(realm, user, session, issuer);
        String encoded = encodeToken(realm, identityToken);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);
        int maxAge = NewCookie.DEFAULT_MAX_AGE;
        if (session.isRememberMe()) {
            maxAge = realm.getSsoSessionMaxLifespan();
        }
        logger.debugv("Create login cookie - name: {0}, path: {1}, max-age: {2}", KEYCLOAK_IDENTITY_COOKIE, cookiePath, maxAge);
        CookieHelper.addCookie(KEYCLOAK_IDENTITY_COOKIE, encoded, cookiePath, null, null, maxAge, secureOnly, true);
        //builder.cookie(new NewCookie(cookieName, encoded, cookiePath, null, null, maxAge, secureOnly));// todo httponly , true);

        String sessionCookieValue = realm.getName() + "/" + user.getId();
        if (session != null) {
            sessionCookieValue += "/" + session.getId();
        }
        // THIS SHOULD NOT BE A HTTPONLY COOKIE!  It is used for OpenID Connect Iframe Session support!
        // Max age should be set to the max lifespan of the session as it's used to invalidate old-sessions on re-login
        CookieHelper.addCookie(KEYCLOAK_SESSION_COOKIE, sessionCookieValue, cookiePath, null, null, realm.getSsoSessionMaxLifespan(), secureOnly, false);

    }

    public static void createRememberMeCookie(RealmModel realm, String username, UriInfo uriInfo, ClientConnection connection) {
        String path = getIdentityCookiePath(realm, uriInfo);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);
        // remember me cookie should be persistent (hardcoded to 365 days for now)
        //NewCookie cookie = new NewCookie(KEYCLOAK_REMEMBER_ME, "true", path, null, null, realm.getCentralLoginLifespan(), secureOnly);// todo httponly , true);
        CookieHelper.addCookie(KEYCLOAK_REMEMBER_ME, "username:" + username, path, null, null, 31536000, secureOnly, true);
    }

    public static String getRememberMeUsername(RealmModel realm, HttpHeaders headers) {
        if (realm.isRememberMe()) {
            Cookie cookie = headers.getCookies().get(AuthenticationManager.KEYCLOAK_REMEMBER_ME);
            if (cookie != null) {
                String value = cookie.getValue();
                String[] s = value.split(":");
                if (s[0].equals("username") && s.length == 2) {
                    return s[1];
                }
            }
        }
        return null;
    }

    protected static String encodeToken(RealmModel realm, Object token) {
        String encodedToken = new JWSBuilder()
                .jsonContent(token)
                .rsa256(realm.getPrivateKey());
        return encodedToken;
    }

    public static void expireIdentityCookie(RealmModel realm, UriInfo uriInfo, ClientConnection connection) {
        logger.debug("Expiring identity cookie");
        String path = getIdentityCookiePath(realm, uriInfo);
        expireCookie(realm, KEYCLOAK_IDENTITY_COOKIE, path, true, connection);
        expireCookie(realm, KEYCLOAK_SESSION_COOKIE, path, false, connection);
    }
    public static void expireRememberMeCookie(RealmModel realm, UriInfo uriInfo, ClientConnection connection) {
        logger.debug("Expiring remember me cookie");
        String path = getIdentityCookiePath(realm, uriInfo);
        String cookieName = KEYCLOAK_REMEMBER_ME;
        expireCookie(realm, cookieName, path, true, connection);
    }

    protected static String getIdentityCookiePath(RealmModel realm, UriInfo uriInfo) {
        return getRealmCookiePath(realm, uriInfo);
    }

    public static String getRealmCookiePath(RealmModel realm, UriInfo uriInfo) {
        URI uri = RealmsResource.realmBaseUrl(uriInfo).build(realm.getName());
        return uri.getRawPath();
    }

    public static void expireCookie(RealmModel realm, String cookieName, String path, boolean httpOnly, ClientConnection connection) {
        logger.debugv("Expiring cookie: {0} path: {1}", cookieName, path);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);;
        CookieHelper.addCookie(cookieName, "", path, null, "Expiring cookie", 0, secureOnly, httpOnly);
    }

    public AuthResult authenticateIdentityCookie(KeycloakSession session, RealmModel realm, UriInfo uriInfo, ClientConnection connection, HttpHeaders headers) {
        return authenticateIdentityCookie(session, realm, uriInfo, connection, headers, true);
    }

    public static AuthResult authenticateIdentityCookie(KeycloakSession session, RealmModel realm, UriInfo uriInfo, ClientConnection connection, HttpHeaders headers, boolean checkActive) {
        Cookie cookie = headers.getCookies().get(KEYCLOAK_IDENTITY_COOKIE);
        if (cookie == null || "".equals(cookie.getValue())) {
            logger.debugv("Could not find cookie: {0}", KEYCLOAK_IDENTITY_COOKIE);
            return null;
        }

        String tokenString = cookie.getValue();
        AuthResult authResult = verifyIdentityToken(session, realm, uriInfo, connection, checkActive, tokenString, headers);
        if (authResult == null) {
            expireIdentityCookie(realm, uriInfo, connection);
            return null;
        }
        authResult.getSession().setLastSessionRefresh(Time.currentTime());
        return authResult;
    }

    public Response checkNonFormAuthentication(KeycloakSession session, ClientSessionModel clientSession, RealmModel realm, UriInfo uriInfo,
                                               HttpRequest request,
                                               ClientConnection clientConnection, HttpHeaders headers,
                                               EventBuilder event) {
        AuthResult authResult = authenticateIdentityCookie(session, realm, uriInfo, clientConnection, headers, true);
        if (authResult != null) {
            UserModel user = authResult.getUser();
            UserSessionModel userSession = authResult.getSession();
            TokenManager.attachClientSession(userSession, clientSession);
            event.user(user).session(userSession).detail(Details.AUTH_METHOD, "sso");
            return nextActionAfterAuthentication(session, userSession, clientSession, clientConnection, request, uriInfo, event);
        }
        return null;
    }



    public static Response redirectAfterSuccessfulFlow(KeycloakSession session, RealmModel realm, UserSessionModel userSession,
                                                ClientSessionModel clientSession,
                                                HttpRequest request, UriInfo uriInfo, ClientConnection clientConnection) {
        Cookie sessionCookie = request.getHttpHeaders().getCookies().get(AuthenticationManager.KEYCLOAK_SESSION_COOKIE);
        if (sessionCookie != null) {

            String[] split = sessionCookie.getValue().split("/");
            if (split.length >= 3) {
                String oldSessionId = split[2];
                if (!oldSessionId.equals(userSession.getId())) {
                    UserSessionModel oldSession = session.sessions().getUserSession(realm, oldSessionId);
                    if (oldSession != null) {
                        logger.debugv("Removing old user session: session: {0}", oldSessionId);
                        session.sessions().removeUserSession(realm, oldSession);
                    }
                }
            }
        }
        if (userSession.getState() != UserSessionModel.State.LOGGED_IN) userSession.setState(UserSessionModel.State.LOGGED_IN);
        // refresh the cookies!
        createLoginCookie(realm, userSession.getUser(), userSession, uriInfo, clientConnection);
        if (userSession.isRememberMe()) createRememberMeCookie(realm, userSession.getUser().getUsername(), uriInfo, clientConnection);
        LoginProtocol protocol = session.getProvider(LoginProtocol.class, clientSession.getAuthMethod());
        protocol.setRealm(realm)
                .setHttpHeaders(request.getHttpHeaders())
                .setUriInfo(uriInfo);
        return protocol.authenticated(userSession, new ClientSessionCode(realm, clientSession));

    }

    public static Response nextActionAfterAuthentication(KeycloakSession session, UserSessionModel userSession, ClientSessionModel clientSession,
                                                  ClientConnection clientConnection,
                                                  HttpRequest request, UriInfo uriInfo, EventBuilder event) {
        RealmModel realm = clientSession.getRealm();
        UserModel user = userSession.getUser();
        isForcePasswordUpdateRequired(realm, user);
        isTotpConfigurationRequired(realm, user);
        isEmailVerificationRequired(realm, user);
        ClientModel client = clientSession.getClient();

        ClientSessionCode accessCode = new ClientSessionCode(realm, clientSession);

        logger.debugv("processAccessCode: go to oauth page?: {0}", client.isConsentRequired());

        event.detail(Details.CODE_ID, clientSession.getId());

        Set<String> requiredActions = user.getRequiredActions();
        if (!requiredActions.isEmpty()) {
            Iterator<String> i = user.getRequiredActions().iterator();
            String action = i.next();
            
            if (action.equals(UserModel.RequiredAction.VERIFY_EMAIL.name()) && Validation.isBlank(user.getEmail())) {
                if (i.hasNext())
                    action = i.next();
                else
                    action = null;
            }

            if (action != null) {
                accessCode.setRequiredAction(RequiredAction.valueOf(action));

                LoginFormsProvider loginFormsProvider = session.getProvider(LoginFormsProvider.class).setClientSessionCode(accessCode.getCode())
                        .setUser(user);
                if (action.equals(UserModel.RequiredAction.VERIFY_EMAIL.name())) {
                    event.clone().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail()).success();
                    LoginActionsService.createActionCookie(realm, uriInfo, clientConnection, userSession.getId());
                }

                return loginFormsProvider.createResponse(RequiredAction.valueOf(action));
            }
        }

        if (client.isConsentRequired()) {

            UserConsentModel grantedConsent = user.getConsentByClient(client.getId());

            List<RoleModel> realmRoles = new LinkedList<RoleModel>();
            MultivaluedMap<String, RoleModel> resourceRoles = new MultivaluedMapImpl<String, RoleModel>();
            for (RoleModel r : accessCode.getRequestedRoles()) {

                // Consent already granted by user
                if (grantedConsent != null && grantedConsent.isRoleGranted(r)) {
                    continue;
                }

                if (r.getContainer() instanceof RealmModel) {
                    realmRoles.add(r);
                } else {
                    resourceRoles.add(((ClientModel) r.getContainer()).getClientId(), r);
                }
            }

            List<ProtocolMapperModel> protocolMappers = new LinkedList<ProtocolMapperModel>();
            for (ProtocolMapperModel protocolMapper : accessCode.getRequestedProtocolMappers()) {
                if (protocolMapper.isConsentRequired() && protocolMapper.getConsentText() != null) {
                    if (grantedConsent == null || !grantedConsent.isProtocolMapperGranted(protocolMapper)) {
                        protocolMappers.add(protocolMapper);
                    }
                }
            }

            // Skip grant screen if everything was already approved by this user
            if (realmRoles.size() > 0 || resourceRoles.size() > 0 || protocolMappers.size() > 0) {
                accessCode.setAction(ClientSessionModel.Action.OAUTH_GRANT);

                return session.getProvider(LoginFormsProvider.class)
                        .setClientSessionCode(accessCode.getCode())
                        .setAccessRequest(realmRoles, resourceRoles, protocolMappers)
                        .createOAuthGrant(clientSession);
            } else {
                String consentDetail = (grantedConsent != null) ? Details.CONSENT_VALUE_PERSISTED_CONSENT : Details.CONSENT_VALUE_NO_CONSENT_REQUIRED;
                event.detail(Details.CONSENT, consentDetail);
            }
        } else {
            event.detail(Details.CONSENT, Details.CONSENT_VALUE_NO_CONSENT_REQUIRED);
        }

        event.success();
        return redirectAfterSuccessfulFlow(session, realm , userSession, clientSession, request, uriInfo, clientConnection);

    }
    
    private static void isForcePasswordUpdateRequired(RealmModel realm, UserModel user) {
        int daysToExpirePassword = realm.getPasswordPolicy().getDaysToExpirePassword();
        if(daysToExpirePassword != -1) {
            for (UserCredentialValueModel entity : user.getCredentialsDirectly()) {
                if (entity.getType().equals(UserCredentialModel.PASSWORD)) {
                    
                    if(entity.getCreatedDate() == null) {
                        user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                        logger.debug("User is required to update password");
                    } else {
                        long timeElapsed = Time.toMillis(Time.currentTime()) - entity.getCreatedDate();
                        long timeToExpire = TimeUnit.DAYS.toMillis(daysToExpirePassword);
                    
                        if(timeElapsed > timeToExpire) {
                            user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                            logger.debug("User is required to update password");
                        }
                    }
                    break;
                }
            }
        }
    }

    protected static void isTotpConfigurationRequired(RealmModel realm, UserModel user) {
        for (RequiredCredentialModel c : realm.getRequiredCredentials()) {
            if (c.getType().equals(CredentialRepresentation.TOTP) && !user.isTotp()) {
                user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
                logger.debug("User is required to configure totp");
            }
        }
    }

    protected static void isEmailVerificationRequired(RealmModel realm, UserModel user) {
        if (realm.isVerifyEmail() && !user.isEmailVerified()) {
            user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
            logger.debug("User is required to verify email");
        }
    }

    protected static AuthResult verifyIdentityToken(KeycloakSession session, RealmModel realm, UriInfo uriInfo, ClientConnection connection, boolean checkActive, String tokenString, HttpHeaders headers) {
	logger.warn( "verifyIdentityToken" );
        try {
            AccessToken token = RSATokenVerifier.verifyToken(tokenString, realm.getPublicKey(), Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName()), checkActive);
            if (checkActive) {
                if (!token.isActive() || token.getIssuedAt() < realm.getNotBefore()) {
                    logger.warn("identity cookie expired");
                    return null;
                } else {
                    logger.warnv("token active - active: {0}, issued-at: {1}, not-before: {2}", token.isActive(), token.getIssuedAt(), realm.getNotBefore());
                }
            }

            UserModel user = session.users().getUserById(token.getSubject(), realm);
            if (user == null || !user.isEnabled() ) {
                logger.warn("Unknown user in identity token");
                return null;
            }

            UserSessionModel userSession = session.sessions().getUserSession(realm, token.getSessionState());
            if (!isSessionValid(realm, userSession)) {
                if (userSession != null) backchannelLogout(session, realm, userSession, uriInfo, connection, headers, true);
                logger.warn("User session not active");
                return null;
            }

            return new AuthResult(user, userSession, token);
        } catch (VerificationException e) {
            logger.warn("Failed to verify identity token", e);
        }
        return null;
    }

    public AuthenticationStatus authenticateForm(KeycloakSession session, ClientConnection clientConnection, RealmModel realm, MultivaluedMap<String, String> formData) {
        String username = formData.getFirst(FORM_USERNAME);
        if (username == null) {
            logger.debug("Username not provided");
            return AuthenticationStatus.INVALID_USER;
        }

        if (realm.isBruteForceProtected()) {
            if (protector.isTemporarilyDisabled(session, realm, username)) {
                return AuthenticationStatus.ACCOUNT_TEMPORARILY_DISABLED;
            }
        }

        AuthenticationStatus status = authenticateInternal(session, realm, formData, username);
        if (realm.isBruteForceProtected()) {
            switch (status) {
                case SUCCESS:
                    protector.successfulLogin(realm, username, clientConnection);
                    break;
                case FAILED:
                case MISSING_TOTP:
                case MISSING_PASSWORD:
                case INVALID_CREDENTIALS:
                    protector.failedLogin(realm, username, clientConnection);
                    break;
                case INVALID_USER:
                    protector.invalidUser(realm, username, clientConnection);
                    break;
                default:
                    break;
            }
        }

        return status;
    }

    protected AuthenticationStatus authenticateInternal(KeycloakSession session, RealmModel realm, MultivaluedMap<String, String> formData, String username) {
        UserModel user = KeycloakModelUtils.findUserByNameOrEmail(session, realm, username);

        if (user == null) {
            logger.debugv("User {0} not found", username);
            return AuthenticationStatus.INVALID_USER;
        }

        Set<String> types = new HashSet<String>();

        for (RequiredCredentialModel credential : realm.getRequiredCredentials()) {
            types.add(credential.getType());
        }

        if (types.contains(CredentialRepresentation.PASSWORD)) {
            List<UserCredentialModel> credentials = new LinkedList<UserCredentialModel>();

            String password = formData.getFirst(CredentialRepresentation.PASSWORD);
            if (password != null) {
                credentials.add(UserCredentialModel.password(password));
            }

            String passwordToken = formData.getFirst(CredentialRepresentation.PASSWORD_TOKEN);
            if (passwordToken != null) {
                credentials.add(UserCredentialModel.passwordToken(passwordToken));
            }

            String totp = formData.getFirst(CredentialRepresentation.TOTP);
            if (totp != null) {
                credentials.add(UserCredentialModel.totp(totp));
            }

            if ((password == null || password.isEmpty()) && (passwordToken == null || passwordToken.isEmpty())) {
                logger.debug("Password not provided");
                return AuthenticationStatus.MISSING_PASSWORD;
            }

            logger.debugv("validating password for user: {0}", username);

            if (!session.users().validCredentials(realm, user, credentials)) {
                return AuthenticationStatus.INVALID_CREDENTIALS;
            }

            if (!user.isEnabled()) {
                return AuthenticationStatus.ACCOUNT_DISABLED;
            }

            if (user.isTotp() && totp == null) {
                return AuthenticationStatus.MISSING_TOTP;
            }

            if (!user.getRequiredActions().isEmpty()) {
                return AuthenticationStatus.ACTIONS_REQUIRED;
            } else {
                return AuthenticationStatus.SUCCESS;
            }
        } else if (types.contains(CredentialRepresentation.SECRET)) {
            String secret = formData.getFirst(CredentialRepresentation.SECRET);
            if (secret == null) {
                logger.debug("Secret not provided");
                return AuthenticationStatus.MISSING_PASSWORD;
            }
            if (!session.users().validCredentials(realm, user, UserCredentialModel.secret(secret))) {
                return AuthenticationStatus.INVALID_CREDENTIALS;
            }
            if (!user.isEnabled()) {
                return AuthenticationStatus.ACCOUNT_DISABLED;
            }
            if (!user.getRequiredActions().isEmpty()) {
                return AuthenticationStatus.ACTIONS_REQUIRED;
            } else {
                return AuthenticationStatus.SUCCESS;
            }
        } else {
            logger.warn("Do not know how to authenticate user");
            return AuthenticationStatus.FAILED;
        }
    }

    public enum AuthenticationStatus {
        SUCCESS, ACCOUNT_TEMPORARILY_DISABLED, ACCOUNT_DISABLED, ACTIONS_REQUIRED, INVALID_USER, INVALID_CREDENTIALS, MISSING_PASSWORD, MISSING_TOTP, FAILED
    }

    public static class AuthResult {
        private final UserModel user;
        private final UserSessionModel session;
        private final AccessToken token;

        public AuthResult(UserModel user, UserSessionModel session, AccessToken token) {
            this.user = user;
            this.session = session;
            this.token = token;
        }

        public UserSessionModel getSession() {
            return session;
        }

        public UserModel getUser() {
            return user;
        }

        public AccessToken getToken() {
            return token;
        }
    }

}
