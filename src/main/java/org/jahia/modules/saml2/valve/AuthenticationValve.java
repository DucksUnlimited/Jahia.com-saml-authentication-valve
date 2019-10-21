package org.jahia.modules.saml2.valve;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import javax.jcr.RepositoryException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.jahia.api.Constants;
import org.jahia.bin.Login;
import org.jahia.modules.saml2.SAML2Constants;
import org.jahia.modules.saml2.SAML2Util;
import org.jahia.modules.saml2.admin.SAML2SettingsService;
import org.jahia.modules.saml2.utils.JCRConstants;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.AutoRegisteredBaseAuthValve;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.seo.urlrewrite.ServerNameToSiteMapper;
import org.jahia.services.sites.JahiaSite;
import org.jahia.services.sites.JahiaSitesService;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.profile.SAML2Profile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class AuthenticationValve extends AutoRegisteredBaseAuthValve {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationValve.class);
    private static final String CMS_PREFIX = "/cms";
    private static final String DEFAULT_LOCALE = "en_US";
    private static final String REDIRECT = "redirect";
    private SAML2SettingsService saml2SettingsService;
    private JCRSessionWrapper sessionWrapper;
    private JahiaUserManagerService jahiaUserManagerService;

    @Override
    public void invoke(final Object context,
            final ValveContext valveContext) throws PipelineException {
        final AuthValveContext authContext = (AuthValveContext) context;
        final HttpServletRequest request = authContext.getRequest();
        final HttpServletResponse response = authContext.getResponse();

        final boolean isSAMLLoginProcess = CMS_PREFIX.equals(request.getServletPath())
                && (Login.getMapping()).equals(request.getPathInfo());

        final boolean isSAMLIncomingLoginProcess = CMS_PREFIX.equals(request.getServletPath())
                && (Login.getMapping() + ".SAML.incoming").equals(request.getPathInfo());

        // Récupération de la siteKey passée en paramètre
        final String siteKey = ServerNameToSiteMapper.getSiteKeyByServerName(request);

        boolean enabled = false;
        if (!StringUtils.isEmpty(siteKey)) {
            try {
                enabled = JCRTemplate.getInstance().doExecuteWithSystemSession(new JCRCallback<Boolean>() {
                    @Override
                    public Boolean doInJCR(JCRSessionWrapper session) {
                        try {
                            final JahiaSitesService siteService = JahiaSitesService.getInstance();
                            final JahiaSite site = siteService.getSiteByKey(siteKey, session);
                            final List<String> installedModules = site.getInstalledModules();
                            return installedModules.contains("saml-authentication-valve");
                        } catch (RepositoryException ex) {
                            LOGGER.error("Impossible to verify the current site", ex);
                        }
                        return false;
                    }
                });
            } catch (RepositoryException ex) {
                LOGGER.error(String.format("Impossible to check if the SAML is enabled for %s"), siteKey);
            }
        }
        if (enabled) {

            // This is the starting process of the SAML authentication which redirects the user to the IDP login screen
            if (isSAMLLoginProcess) {
                SAML2Util.initialize(() -> {
                    // Storing redirect url into cookie to be used when the request is send from IDP to continue the
                    // access to the secure resource
                    final String redirectParam = request.getParameter(REDIRECT);
                    if (redirectParam != null) {
                        response.addCookie(new Cookie(REDIRECT, redirectParam.replaceAll("\n\r", "")));
                    }
                    final String siteParam = request.getParameter(SAML2Constants.SITE);
                    if (siteParam != null) {
                        response.addCookie(new Cookie(siteKey, siteParam.replaceAll("\n\r", "")));
                    }
                    final SAML2Client client = SAML2Util.getSAML2Client(saml2SettingsService, request, siteKey);
                    final J2EContext webContext = new J2EContext(request, response);
                    final HttpAction action = client.redirect(webContext);
                    response.getWriter().flush();
                    LOGGER.info(action.getMessage());
                });
            } else if (isSAMLIncomingLoginProcess) {
                SAML2Util.initialize(() -> {
                    final SAML2Client client = SAML2Util.getSAML2Client(saml2SettingsService, request, siteKey);
                    final J2EContext webContext = new J2EContext(request, response);
                    final SAML2Credentials saml2Credentials = client.getCredentials(webContext);
                    final SAML2Profile saml2Profile = client.getUserProfile(saml2Credentials, webContext);
                    final String email = saml2Profile.getEmail();
                    LOGGER.debug("email of SAML Profile: " + email);

                    JCRUserNode jahiaUserNode = null;
                    if (StringUtils.isNotEmpty(email)) {
                        // TODO: split this processing of the user at the back-end level in the same way than the OAuth modules
                        jahiaUserNode = this.processSSOUserInJcr(email, saml2Profile, request, siteKey);
                        final JahiaUser jahiaUser = jahiaUserNode.getJahiaUser();
                        if (jahiaUser.isAccountLocked()) {
                            LOGGER.info("Login failed. Account is locked for user " + email);
                            valveContext.invokeNext(context);
                            return;
                        }
                        authContext.getSessionFactory().setCurrentUser(jahiaUser);
                        request.getSession().setAttribute(Constants.SESSION_USER, jahiaUser);

                        request.setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.OK);

                        // Get the redirection URL from the cookie, if not set takes the value is taken from the site settings
                        String redirection = retrieveRedirectUrl(request, siteKey);
                        response.sendRedirect(redirection);
                    } else {
                        valveContext.invokeNext(context);
                    }
                    return;
                });
            }
        } else {
            valveContext.invokeNext(context);
        }

    }

    /**
     * Update user is exist or create a new user for site with sso profile properties.
     *
     * @param email
     * @param saml2Profile
     * @param request
     * @return
     * @throws RepositoryException
     */
    private JCRUserNode processSSOUserInJcr(String email, SAML2Profile saml2Profile, HttpServletRequest request, String siteKey) throws RepositoryException {
        this.sessionWrapper = JCRSessionFactory.getInstance()
                .getCurrentSystemSession(
                        null,
                        (request.getLocale() != null) ? request.getLocale() : new Locale(DEFAULT_LOCALE),
                        new Locale(DEFAULT_LOCALE));
        JCRUserNode ssoUserNode = null;
        if (this.jahiaUserManagerService.userExists(email, siteKey)) {
            ssoUserNode = this.jahiaUserManagerService.lookupUser(email, siteKey, this.sessionWrapper);
            JCRNodeWrapper jcrNodeWrapper = ssoUserNode.getDecoratedNode();
            boolean isUpdated = this.updateProperties(jcrNodeWrapper, saml2Profile);
            //saving session if any property is updated for user.
            if (isUpdated) {
                this.sessionWrapper.save();
            }
        } else {
            ssoUserNode = jahiaUserManagerService.createUser(email, siteKey,
                    RandomStringUtils.randomAscii(18), this.initialProperties(saml2Profile), this.sessionWrapper);
            this.sessionWrapper.save();
        }
        return ssoUserNode;
    }

    /**
     * properties for new user.
     */
    private Properties initialProperties(SAML2Profile saml2Profile) {
        Properties properties = new Properties();
        properties.setProperty(JCRConstants.USER_PROPERTY_EMAIL, this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_EMAIL, saml2Profile));
        properties.setProperty(JCRConstants.USER_PROPERTY_LASTNAME, this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_LASTNAME, saml2Profile));
        properties.setProperty(JCRConstants.USER_PROPERTY_FIRSTNAME, this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_FIRSTNAME, saml2Profile));
        return properties;
    }

    /**
     * Update properties for existing user node.
     *
     * @param jcrNodeWrapper
     * @param saml2Profile
     * @throws RepositoryException
     */
    private boolean updateProperties(JCRNodeWrapper jcrNodeWrapper, SAML2Profile saml2Profile) throws RepositoryException {
        boolean isUpdated = false;
        String email = this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_EMAIL, saml2Profile);
        if (Objects.isNull(jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_EMAIL))
                || !jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_EMAIL).equals(email)) {
            jcrNodeWrapper.setProperty(JCRConstants.USER_PROPERTY_EMAIL, email);
            isUpdated = true;
        }

        String lastname = this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_LASTNAME, saml2Profile);
        if (Objects.isNull(jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_LASTNAME))
                || !jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_LASTNAME).equals(lastname)) {
            jcrNodeWrapper.setProperty(JCRConstants.USER_PROPERTY_LASTNAME, lastname);
            isUpdated = true;
        }

        String firstname = this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_FIRSTNAME, saml2Profile);
        if (Objects.isNull(jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_FIRSTNAME))
                || !jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_FIRSTNAME).equals(firstname)) {
            jcrNodeWrapper.setProperty(JCRConstants.USER_PROPERTY_FIRSTNAME, firstname);
            isUpdated = true;
        }

        return isUpdated;
    }

    /**
     * Fetch user profile attributes from SAML profile.
     *
     * @param name
     * @param saml2Profile
     * @return
     */
    private String getProfileAttribute(String name, SAML2Profile saml2Profile) {
        ArrayList<String> strings = saml2Profile.getAttribute(name, ArrayList.class);
        if (Objects.nonNull(strings)) {
            return strings.get(0);
        }
        return "";
    }

    /**
     * Gets the redirection URL from the cookie, if not set takes the value is taken from the site settings
     *
     * @param request : the http request
     * @return the redirection URL
     */
    private String retrieveRedirectUrl(HttpServletRequest request, String siteKey) {
        String redirection = SAML2Util.getCookieValue(request, REDIRECT);
        if (StringUtils.isEmpty(redirection)) {
            redirection = this.saml2SettingsService.getSettings(siteKey).getPostLoginPath();
            if (StringUtils.isEmpty(redirection)) {
                // default value
                redirection = "/";
            }
        }

        return redirection;
    }

    public void setSaml2SettingsService(final SAML2SettingsService saml2SettingsService) {
        this.saml2SettingsService = saml2SettingsService;
    }

    public void setJahiaUserManagerService(JahiaUserManagerService jahiaUserManagerService) {
        this.jahiaUserManagerService = jahiaUserManagerService;
    }
}
