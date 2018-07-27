/*
 * Copyright 2014 Giannis Dzegoutanis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.params;

import org.bitcoinj.core.NetworkParameters;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

import java.util.Collection;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Utility class that holds all the registered NetworkParameters types used for Address auto discovery.
 * By default only MainNetParams and TestNet3Params are used. If you want to use TestNet2, RegTestParams or
 * UnitTestParams use the register and unregister the TestNet3Params as they don't have their own address
 * version/type code.
 */
public class Networks {
    private static final Pattern bitcoinFamily = Pattern.compile(".*(bitcoin).*");
    private static final Pattern reddcoinFamily = Pattern.compile(".*(reddcoin).*");
    private static final Pattern peercoinFamily = Pattern.compile(".*(peercoin).*");
    private static final Pattern nubitsFamily = Pattern.compile(".*(nubits).*");
    private static final Pattern vpncoinFamily = Pattern.compile(".*(vpncoin).*");
    private static final Pattern clamsFamily = Pattern.compile(".*(clams).*");
    private static final Pattern solarcoinFamily = Pattern.compile(".*(solarcoin).*");
    private static final Pattern bitcoinDiamondFamily = Pattern.compile(".*(bitcoindiamond).*");

    /** Registered networks */
    private static Set<? extends NetworkParameters> networks = ImmutableSet.of(TestNet3Params.get(), MainNetParams.get());

    public static Set<? extends NetworkParameters> get() {
        return networks;
    }

    public static void register(NetworkParameters network) {
        register(Lists.newArrayList(network));
    }

    public static void register(Collection<? extends NetworkParameters> networks) {
        ImmutableSet.Builder<NetworkParameters> builder = ImmutableSet.builder();
        builder.addAll(Networks.networks);
        builder.addAll(networks);
        Networks.networks = builder.build();
    }

    public static void unregister(NetworkParameters network) {
        if (networks.contains(network)) {
            ImmutableSet.Builder<NetworkParameters> builder = ImmutableSet.builder();
            for (NetworkParameters parameters : networks) {
                if (parameters.equals(network))
                    continue;
                builder.add(parameters);
            }
            networks = builder.build();
        }
    }

    public static boolean isFamily(NetworkParameters network, Networks.Family family) {
        return getFamily(network) == family;
    }

    public static boolean isFamily(NetworkParameters network, Networks.Family family1, Networks.Family family2) {
        Networks.Family networkFamily = getFamily(network);
        return networkFamily == family1 || networkFamily == family2;
    }

    public static boolean isFamily(NetworkParameters network, Networks.Family family1, Networks.Family family2, Networks.Family family3) {
        Networks.Family networkFamily = getFamily(network);
        return networkFamily == family1 || networkFamily == family2 || networkFamily == family3;
    }

    public static boolean isFamily(NetworkParameters network, Networks.Family family1, Networks.Family family2, Networks.Family family3, Networks.Family family4) {
        Networks.Family networkFamily = getFamily(network);
        return networkFamily == family1 || networkFamily == family2 || networkFamily == family3 || networkFamily == family4;
    }

    public static boolean isFamily(NetworkParameters network, Networks.Family family1, Networks.Family family2, Networks.Family family3, Networks.Family family4, Networks.Family family5) {
        Networks.Family networkFamily = getFamily(network);
        return networkFamily == family1 || networkFamily == family2 || networkFamily == family3 || networkFamily == family4 || networkFamily == family5;
    }

    public static boolean isFamily(NetworkParameters network, Networks.Family family1, Networks.Family family2, Networks.Family family3, Networks.Family family4, Networks.Family family5, Networks.Family family6) {
        Networks.Family networkFamily = getFamily(network);
        return networkFamily == family1 || networkFamily == family2 || networkFamily == family3 || networkFamily == family4 || networkFamily == family5 || networkFamily == family6;
    }

    public static Networks.Family getFamily(NetworkParameters network) {
        if (network != null && network.getFamily() != null) {
            if (bitcoinDiamondFamily.matcher(network.getFamilyString()).matches()) {
                return Family.BITCOINDIAMOND;
            } else if (peercoinFamily.matcher(network.getFamilyString()).matches()) {
                return Networks.Family.PEERCOIN;
            } else if (nubitsFamily.matcher(network.getFamilyString()).matches()) {
                return Networks.Family.NUBITS;
            } else if (reddcoinFamily.matcher(network.getFamilyString()).matches()) {
                return Networks.Family.REDDCOIN;
            } else if (vpncoinFamily.matcher(network.getFamilyString()).matches()) {
                return Networks.Family.VPNCOIN;
            } else if (clamsFamily.matcher(network.getFamilyString()).matches()) {
                return Networks.Family.CLAMS;
            } else if (bitcoinFamily.matcher(network.getFamilyString()).matches()) {
                return Family.BITCOIN;
            } else {
                return solarcoinFamily.matcher(network.getFamilyString()).matches() ? Networks.Family.SOLARCOIN : Networks.Family.BITCOIN;
            }
        } else {
            return Networks.Family.BITCOIN;
        }
    }

    public static enum Family {
        BITCOIN,
        BITCOINDIAMOND,
        REDDCOIN,
        PEERCOIN,
        NUBITS,
        VPNCOIN,
        CLAMS,
        SOLARCOIN;

        private Family() {
        }
    }
}
