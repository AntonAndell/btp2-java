/*
 * Copyright 2022 ICONLOOP Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package foundation.icon.btp.bmv.eth2.score;

import foundation.icon.icx.Wallet;
import foundation.icon.icx.transport.jsonrpc.RpcObject;
import foundation.icon.icx.transport.jsonrpc.RpcValue;
import foundation.icon.test.Log;
import foundation.icon.test.ResultTimeoutException;
import foundation.icon.test.TransactionFailureException;
import foundation.icon.test.TransactionHandler;
import foundation.icon.test.score.Score;
import score.Address;

import java.io.IOException;
import java.math.BigInteger;


public class BMVScore extends Score {

    private static final Log LOG = Log.getGlobal();

    public static BMVScore mustDeploy(
            TransactionHandler txHandler,
            Wallet wallet,
            String srcNetworkID,
            byte[] validatorHash,
            byte[] syncCommittee,
            Address bmc,
            byte[] finalized,
            byte[] etherBmc
    )
            throws ResultTimeoutException, TransactionFailureException, IOException {
        LOG.infoEntering("deploy", "bmv");
        RpcObject params = new RpcObject.Builder()
                .put("srcNetworkID", new RpcValue(srcNetworkID))
                .put("genesisValidatorsHash", new RpcValue(validatorHash))
                .put("syncCommittee", new RpcValue(syncCommittee))
                .put("bmc", new RpcValue(bmc.toString()))
                .put("finalizedHeader", new RpcValue(finalized))
                .put("etherBmc", new RpcValue(etherBmc))
                .build();
        Score score = txHandler.deploy(wallet, getFilePath("bmv-eth2"), params, BigInteger.valueOf(2000000000));
        LOG.info("scoreAddr = " + score.getAddress());
        LOG.infoExiting();
        return new BMVScore(score);
    }

    public BMVScore(Score other) {
        super(other);
    }
}