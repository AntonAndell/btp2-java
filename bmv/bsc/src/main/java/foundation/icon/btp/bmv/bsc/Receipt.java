/*
 * Copyright 2023 ICON Foundation
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
package foundation.icon.btp.bmv.bsc;

import score.Context;
import score.ObjectReader;
import scorex.util.ArrayList;
import scorex.util.Collections;

import java.math.BigInteger;
import java.util.List;

public class Receipt {
    public static final int StatusFailed = 0;
    private byte[] postStatusOrState;
    private BigInteger cumulativeGasUsed;
    private byte[] bloom;
    private List<EventLog> logs;

    public Receipt(byte[] postStatusOrState, BigInteger cumulativeGasUsed,
            byte[] bloom, List<EventLog> logs) {
        this.postStatusOrState = postStatusOrState;
        this.cumulativeGasUsed = cumulativeGasUsed;
        this.bloom = bloom;
        this.logs = Collections.unmodifiableList(logs);
    }

    public static Receipt readObject(ObjectReader r) {
        r.beginList();
        byte[] postStatusOrState = r.readByteArray();
        BigInteger cumulativeGasUsed = r.readBigInteger();
        byte[] bloom = r.readByteArray();
        r.beginList();
        List<EventLog> logs = new ArrayList<>();
        while(r.hasNext()) {
            logs.add(r.read(EventLog.class));
        }
        r.end();
        r.end();
        return new Receipt(postStatusOrState, cumulativeGasUsed, bloom, logs);
    }

    public static Receipt fromBytes(byte[] bytes) {
        return Receipt.readObject(Context.newByteArrayObjectReader("RLP", bytes));
    }

    public int getStatus() {
        return new BigInteger(postStatusOrState).intValue();
    }

    public List<EventLog> getLogs() {
        return logs;
    }
}
