/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.breach.detection.source;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.breach.detection.config.ResolvedSourceConfiguration;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * The offline source as the engine sees it.
 */
public class LocalBlocklistSourceTest {

    private static final String TENANT = "carbon.super";

    private static Path carbonHome;

    /**
     * The real configuration object confines a path to the deployment, so the blocklist files these tests
     * write have to live under a carbon.home. Using it rather than a stub means the tests exercise that
     * confinement instead of bypassing it.
     */
    @BeforeClass
    public void setUp() throws IOException {

        carbonHome = Files.createTempDirectory("carbon-home-");
        carbonHome.toFile().deleteOnExit();
        System.setProperty("carbon.home", carbonHome.toString());
    }

    @Test
    public void declaresItselfOfflineAndCheapSoTheEngineConsultsItFirst() {

        LocalBlocklistSource source = new LocalBlocklistSource();
        assertTrue(source.getPriority() < 500);
        source.shutdown();
    }

    @Test
    public void refusesAListedPasswordAndAcceptsAnUnlistedOne() throws IOException {

        LocalBlocklistSource source = configured(write(Arrays.asList("Password@1", "Qwerty@123")), "plaintext");

        assertEquals(source.check(candidate("Password@1"), TENANT), Decision.REFUSE_BREACHED);
        assertEquals(source.check(candidate("Zx9q!Kt7#Lm2vRb4"), TENANT), Decision.ACCEPT);
        source.shutdown();
    }

    /**
     * A hashed file is compared on its own algorithm, and the candidate is hashed with the same one. If the two
     * sides ever diverged the list would silently stop matching, which is the failure this pins down.
     */
    @Test
    public void aHashedListMatchesTheDigestTheCredentialProduces() throws IOException {

        String digest = BlocklistLoader.digestOf("Password@1", "SHA-1");
        LocalBlocklistSource source = configured(write(Collections.singletonList(digest)), "sha1");

        assertEquals(source.check(candidate("Password@1"), TENANT), Decision.REFUSE_BREACHED);
        assertEquals(source.check(candidate("Password@2"), TENANT), Decision.ACCEPT);
        source.shutdown();
    }

    @Test
    public void withNoFileConfiguredTheSourceIsNotEnabled() {

        LocalBlocklistSource source = new LocalBlocklistSource();
        source.configure(settings());

        assertFalse(source.isEnabled(TENANT));
        assertEquals(source.check(candidate("Password@1"), TENANT), Decision.ACCEPT);
        source.shutdown();
    }

    /**
     * The file dictates the algorithm, so a file with none declared is not something we can compare against.
     */
    @Test
    public void aFileWithNoDeclaredFormatLeavesTheSourceNotConfigured() throws IOException {

        LocalBlocklistSource source = new LocalBlocklistSource();
        source.configure(settings(LocalBlocklistSource.PROPERTY_PATH,
                write(Collections.singletonList("Password@1")).toString()));

        assertFalse(source.isEnabled(TENANT));
        source.shutdown();
    }

    @Test
    public void theOffSwitchParksAConfiguredListWithoutUnpickingIt() throws IOException {

        Path file = write(Collections.singletonList("Password@1"));
        LocalBlocklistSource source = configured(file, "plaintext");
        assertTrue(source.isEnabled(TENANT));

        source.configure(settings(LocalBlocklistSource.PROPERTY_ENABLE, "false",
                LocalBlocklistSource.PROPERTY_PATH, file.toString(),
                LocalBlocklistSource.PROPERTY_FORMAT, "plaintext"));

        assertFalse(source.isEnabled(TENANT));
        assertEquals(source.check(candidate("Password@1"), TENANT), Decision.ACCEPT);
        source.shutdown();
    }

    /**
     * Absent the switch the list runs, so a deployment that never declared one is unaffected.
     */
    @Test
    public void theListRunsWhenNoSwitchIsDeclared() throws IOException {

        LocalBlocklistSource source = configured(write(Collections.singletonList("Password@1")), "plaintext");
        assertTrue(source.isEnabled(TENANT));
        source.shutdown();
    }

    @Test
    public void anUnreadableFileLeavesThePreviouslyLoadedListInEffect() throws IOException {

        Path file = write(Collections.singletonList("Password@1"));
        LocalBlocklistSource source = configured(file, "plaintext");
        Files.delete(file);

        // Reconfiguring against a different path forces a load attempt; the old list must survive it.
        source.configure(settings(LocalBlocklistSource.PROPERTY_PATH, file.toString(),
                LocalBlocklistSource.PROPERTY_FORMAT, "sha1"));

        assertEquals(source.check(candidate("Password@1"), TENANT), Decision.REFUSE_BREACHED,
                "The previous list must stay in effect rather than emptying itself.");
        source.shutdown();
    }

    private LocalBlocklistSource configured(Path file, String format) {

        LocalBlocklistSource source = new LocalBlocklistSource();
        source.configure(settings(LocalBlocklistSource.PROPERTY_PATH, file.toString(),
                LocalBlocklistSource.PROPERTY_FORMAT, format));
        return source;
    }

    private Credential candidate(String password) {

        return new Credential(password.toCharArray());
    }

    /**
     * @param nameValuePairs alternating property name and value.
     */
    private static ResolvedSourceConfiguration settings(String... nameValuePairs) {

        Map<String, String> values = new LinkedHashMap<>();
        for (int i = 0; i < nameValuePairs.length; i += 2) {
            values.put(nameValuePairs[i], nameValuePairs[i + 1]);
        }
        return new ResolvedSourceConfiguration("localList", values);
    }

    private static Path write(List<String> lines) throws IOException {

        Path file = Files.createTempFile(carbonHome, "local-blocklist-", ".txt");
        file.toFile().deleteOnExit();
        Files.write(file, String.join("\n", lines).concat("\n").getBytes(StandardCharsets.UTF_8));
        return file;
    }
}
