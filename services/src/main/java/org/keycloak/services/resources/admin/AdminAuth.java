package org.keycloak.services.resources.admin;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AdminAuth {

    private static final Logger LOGGER = Logger.getLogger(AdminAuth.class);

    private final RealmModel realm;
    private final AccessToken token;
    private final UserModel user;
    private final ClientModel client;

    public AdminAuth(RealmModel realm, AccessToken token, UserModel user, ClientModel client) {
        this.token = token;
        this.realm = realm;

        this.user = user;
        this.client = client;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public UserModel getUser() {
        return user;
    }

    public ClientModel getClient() {
        return client;
    }

    public AccessToken getToken() {
        return token;
    }


    public boolean hasRealmRole(String role) {
        if (client instanceof ClientModel) {
            RoleModel roleModel = realm.getRole(role);
            if (roleModel == null) return false;
            return user.hasRole(roleModel) && client.hasScope(roleModel);
        } else {
            AccessToken.Access access = token.getRealmAccess();
            return access != null && access.isUserInRole(role);
        }
    }

    public boolean hasOneOfRealmRole(String... roles) {
        for (String r : roles) {
            if (hasRealmRole(r)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasAppRole(ClientModel app, String role) {
	LOGGER.warn("hasAppRole: " + role);
        if (client instanceof ClientModel) {
	    LOGGER.warn("ClientModel");
            RoleModel roleModel = app.getRole(role);
            if (roleModel == null)
	    {
		 LOGGER.warn("return false" );
		 return false;
	    }
            return user.hasRole(roleModel) && client.hasScope(roleModel);
        } else {
            LOGGER.warn("AccessToken");
            AccessToken.Access access = token.getResourceAccess(app.getClientId());
            return access != null && access.isUserInRole(role);
        }
    }

    public boolean hasOneOfAppRole(ClientModel app, String... roles) {
	LOGGER.warn("hasOneOfAppRole");
        for (String r : roles) {
	    LOGGER.warn("role: " + r );
            if (hasAppRole(app, r)) {
		LOGGER.warn("true");
                return true;
            }
        }
        LOGGER.warn("false");
        return false;
    }

}
