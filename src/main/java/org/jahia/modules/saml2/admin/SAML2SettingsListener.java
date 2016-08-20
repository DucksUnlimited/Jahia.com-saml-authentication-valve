/**
 * ==========================================================================================
 * =                            JAHIA'S ENTERPRISE DISTRIBUTION                             =
 * ==========================================================================================
 * <p>
 * http://www.jahia.com
 * <p>
 * JAHIA'S ENTERPRISE DISTRIBUTIONS LICENSING - IMPORTANT INFORMATION
 * ==========================================================================================
 * <p>
 * Copyright (C) 2002-2016 Jahia Solutions Group. All rights reserved.
 * <p>
 * This file is part of a Jahia's Enterprise Distribution.
 * <p>
 * Jahia's Enterprise Distributions must be used in accordance with the terms
 * contained in the Jahia Solutions Group Terms & Conditions as well as
 * the Jahia Sustainable Enterprise License (JSEL).
 * <p>
 * For questions regarding licensing, support, production usage...
 * please contact our team at sales@jahia.com or go to http://www.jahia.com/license.
 * <p>
 * ==========================================================================================
 */
package org.jahia.modules.saml2.admin;

import org.jahia.modules.saml2.SAML2Constants;
import org.jahia.services.content.DefaultEventListener;
import org.jahia.services.content.ExternalEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import javax.jcr.observation.Event;
import javax.jcr.observation.EventIterator;

/**
 * Listener to propagate settings info among cluster nodes
 */
public class SAML2SettingsListener extends DefaultEventListener implements ExternalEventListener,
        ApplicationEventPublisherAware {
    private static final Logger LOGGER = LoggerFactory.getLogger(SAML2SettingsListener.class);
    private ApplicationEventPublisher applicationEventPublisher;

    @Override
    public int getEventTypes() {
        return Event.PROPERTY_ADDED + Event.PROPERTY_CHANGED + Event.PROPERTY_REMOVED + Event.NODE_ADDED + Event.NODE_REMOVED;
    }

    @Override
    public String[] getNodeTypes() {
        return new String[]{
            SAML2Constants.SETTINGS_NODE_TYPE
        };
    }

    @Override
    public void onEvent(final EventIterator events) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Firing off SAML2SettingsChangedEvent");
        }
        applicationEventPublisher.publishEvent(new SAML2SettingsChangedListener.SAML2SettingsChangedEvent(events));
    }

    public void setApplicationEventPublisher(final ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }
}
