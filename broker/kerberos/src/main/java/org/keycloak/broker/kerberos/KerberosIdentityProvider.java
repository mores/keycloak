package org.keycloak.broker.kerberos;

import java.net.URI;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.keycloak.broker.kerberos.impl.KerberosServerSubjectAuthenticator;
import org.keycloak.broker.kerberos.impl.SPNEGOAuthenticator;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.AuthenticationResponse;
import org.keycloak.broker.provider.FederatedIdentity;
import org.keycloak.models.FederatedIdentityModel;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KerberosIdentityProvider extends AbstractIdentityProvider<KerberosIdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(KerberosIdentityProvider.class);

    public KerberosIdentityProvider(KerberosIdentityProviderConfig config) {
        super(config);
    }


    @Override
    public AuthenticationResponse handleRequest(AuthenticationRequest request) {
        // TODO: trace
        logger.info("handleRequest");

        // Just redirect to handleResponse for now
        URI redirectUri = UriBuilder.fromUri(request.getRedirectUri()).queryParam(KerberosConstants.RELAY_STATE_PARAM, request.getState()).build();
        Response response = Response.status(302)
                .location(redirectUri)
                .build();

        return AuthenticationResponse.fromResponse(response);
    }


    @Override
    public String getRelayState(AuthenticationRequest request) {
        UriInfo uriInfo = request.getUriInfo();
        return uriInfo.getQueryParameters().getFirst(KerberosConstants.RELAY_STATE_PARAM);
    }


    @Override
    public AuthenticationResponse handleResponse(AuthenticationRequest request) {
        String authHeader = request.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // Case when we don't yet have any Negotiate header
        if (authHeader == null) {
            return sendNegotiateResponse(null);
        }

        String[] tokens = authHeader.split(" ");
        if (tokens.length != 2) {
            logger.warn("Invalid length of tokens: " + tokens.length);
            return sendNegotiateResponse(null);
        } else if (!KerberosConstants.NEGOTIATE.equalsIgnoreCase(tokens[0])) {
            logger.warn("Unknown scheme " + tokens[0]);
            return sendNegotiateResponse(null);
        } else {
            String spnegoToken = tokens[1];
            SPNEGOAuthenticator spnegoAuthenticator = createSPNEGOAuthenticator(spnegoToken);
            spnegoAuthenticator.authenticate();

            if (spnegoAuthenticator.isAuthenticated()) {
                FederatedIdentity federatedIdentity = getFederatedIdentity(spnegoAuthenticator);
                return AuthenticationResponse.end(federatedIdentity);
            }  else {
                return sendNegotiateResponse(spnegoAuthenticator.getResponseToken());
            }
        }
    }

    protected SPNEGOAuthenticator createSPNEGOAuthenticator(String spnegoToken) {
        KerberosServerSubjectAuthenticator kerberosAuth = createKerberosSubjectAuthenticator();
        return new SPNEGOAuthenticator(kerberosAuth, spnegoToken);
    }

    protected KerberosServerSubjectAuthenticator createKerberosSubjectAuthenticator() {
        return new KerberosServerSubjectAuthenticator(getConfig());
    }


    /**
     * Send response with header "WWW-Authenticate: Negotiate {negotiateToken}"
     *
     * @param negotiateToken token to be send back in response or null if just "WWW-Authenticate: Negotiate" should be sent
     * @return AuthenticationResponse
     */
    protected AuthenticationResponse sendNegotiateResponse(String negotiateToken) {
        String negotiateHeader = negotiateToken == null ? KerberosConstants.NEGOTIATE : KerberosConstants.NEGOTIATE + " " + negotiateToken;

        Response response = Response.status(Response.Status.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, negotiateHeader)
                .build();
        return AuthenticationResponse.fromResponse(response);
    }


    protected FederatedIdentity getFederatedIdentity(SPNEGOAuthenticator spnegoAuthenticator) {
        String kerberosUsername = spnegoAuthenticator.getPrincipal();
        FederatedIdentity user = new FederatedIdentity(kerberosUsername);
        user.setUsername(kerberosUsername);

        // Just guessing email, but likely can't do anything better...
        String[] tokens = kerberosUsername.split("@");
        String email = tokens[0] + "@" + tokens[1].toLowerCase();
        user.setEmail(email);
        return user;
    }


    @Override
    public Response retrieveToken(FederatedIdentityModel identity) {
        logger.warn("retrieveToken unsupported for Kerberos right now");
        return null;
    }
}