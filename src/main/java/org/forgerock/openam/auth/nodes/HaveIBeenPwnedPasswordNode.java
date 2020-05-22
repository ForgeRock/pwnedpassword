/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017 ForgeRock AS.
 */
/**
 * jon.knight@forgerock.com
 *
 * A node that returns true if the user's email address is recorded as breached by the HaveIBeenPwned website (http://haveibeenpwned.com)
 * or false if no breach has been recorded
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import javax.inject.Inject;
import org.forgerock.openam.annotations.sm.Attribute;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;

import org.apache.commons.codec.binary.Hex;


@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = HaveIBeenPwnedPasswordNode.Config.class)
public class HaveIBeenPwnedPasswordNode extends AbstractDecisionNode {


    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100)
        default String apiKey() { return "apiKey"; }

        @Attribute(order = 200)
        default String userAgent() { return "ForgeRock"; }

        @Attribute(order = 300)
        default String password() { return "password"; }

        @Attribute(order = 400)
        default int threshold() { return 0; }

        @Attribute(order = 500)
        default String breaches() { return "breaches"; }        
    }



    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "HaveIBeenPwnedPasswordNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public HaveIBeenPwnedPasswordNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        String pass = context.transientState.get(config.password()).asString();
        if (pass == null) pass = context.sharedState.get(config.password()).asString();
        if (pass == null) {
            debug.error("[" + DEBUG_FILE + "]: " + "couldn't find password variable in transient or shared state: " + config.password());
            // Assume compromised state
            return goTo(true).build();
        }
        String hex = null;
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(pass.getBytes("UTF-8"));
            hex = Hex.encodeHexString(sha1.digest());
            debug.message("[" + DEBUG_FILE + "]: " + "SHA1 hash of password: " + hex);
        } catch (Exception e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Hash failed");
            // Assume compromised state
            return goTo(true).build();
        }
        int breaches = haveIBeenPwnedPassword(hex);
        JsonValue newSharedState = context.sharedState.copy();
        if (config.breaches() != null) newSharedState.put(config.breaches(), breaches);
        return goTo(breaches > config.threshold()).replaceSharedState(newSharedState).build();
    }


    private int haveIBeenPwnedPassword(String hex) {
        hex = hex.toUpperCase();
        String prefix = hex.substring(0,5);
        int response = 0;
        try {
            URL url = new URL("https://api.pwnedpasswords.com/range/" + prefix);
            debug.message("[" + DEBUG_FILE + "]: url = " + url);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", config.userAgent());
            conn.setRequestProperty("hibp-api-key", config.apiKey());
            
            if (conn.getResponseCode() != 200) {
                debug.error("[" + DEBUG_FILE + "]: HTTP failed, response code:" + conn.getResponseCode());
                throw new RuntimeException("[" + DEBUG_FILE + "]: HTTP error code : " + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            while ((output = br.readLine()) != null) {
                if (prefix.concat(output).startsWith(hex)) {
                    debug.message("[" + DEBUG_FILE + "]: found matching password: " + output);
                    // Compromised password match
                    String[] parts;
                    parts = output.split(":");
                    int breaches = Integer.parseInt(parts[1]);
                    // If password matched and number of hits is greater than threshold then compromised is true
                    if (breaches > config.threshold()) response = breaches;

                }
            }
            conn.disconnect();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // No matching password found
        debug.message("[" + DEBUG_FILE + "]: Breaches " + response);
        return response;
    }

}
