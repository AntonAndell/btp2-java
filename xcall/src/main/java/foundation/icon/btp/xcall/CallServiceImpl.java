/*
 * Copyright 2022 ICON Foundation
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

package foundation.icon.btp.xcall;

import foundation.icon.btp.lib.BSH;
import foundation.icon.btp.lib.BTPAddress;
import score.Address;
import score.ArrayDB;
import score.BranchDB;
import score.Context;
import score.DictDB;
import score.RevertedException;
import score.UserRevertedException;
import score.VarDB;
import score.annotation.EventLog;
import score.annotation.External;
import score.annotation.Optional;
import score.annotation.Payable;
import scorex.util.HashMap;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class CallServiceImpl implements BSH, CallService, FeeManage {
    public static final int MAX_DATA_SIZE = 2048;
    public static final int MAX_ROLLBACK_SIZE = 1024;

    private final VarDB<String> networkId = Context.newVarDB("NetworkId", String.class);
    private final VarDB<NetworkAddress> networkAddress = Context.newVarDB("NetworkAddress", NetworkAddress.class);
    private final VarDB<BigInteger> sn = Context.newVarDB("sn", BigInteger.class);
    private final VarDB<BigInteger> reqId = Context.newVarDB("reqId", BigInteger.class);
    private final DictDB<String, Address> connections = Context.newDictDB("connections", Address.class);
    private final DictDB<Address, String> protocols = Context.newDictDB("protocols", String.class);
    private final ArrayDB<String> availableProtocols = Context.newArrayDB("availableProtocols", String.class);

    private final DictDB<BigInteger, CallRequest> requests = Context.newDictDB("requests", CallRequest.class);
    private final DictDB<BigInteger, CSMessageRequest> proxyReqs = Context.newDictDB("proxyReqs", CSMessageRequest.class);
    private final BranchDB<String, DictDB<BigInteger, byte[]>> proxyRequestProtocols = Context.newBranchDB("responseProtocols", byte[].class);
    private final BranchDB<String, DictDB<BigInteger, byte[]>> responseProtocols = Context.newBranchDB("responseProtocols", byte[].class);

    // for fee-related operations
    private final VarDB<Address> admin = Context.newVarDB("admin", Address.class);
    private final VarDB<Address> feeHandler = Context.newVarDB("feeHandler", Address.class);
    private final VarDB<BigInteger> protocolFee = Context.newVarDB("protocolFee", BigInteger.class);

    public CallServiceImpl(String _networkId) {
        if (networkId.get() == null ) {
            networkId.set(_networkId);

        }
    }

    /* Implementation-specific external */
    @External(readonly=true)
    public String getNetworkAddress() {
        return new NetworkAddress(networkId.get(), Context.getAddress()).toString();
    }

    private void checkCallerOrThrow(Address caller, String errMsg) {
        Context.require(Context.getCaller().equals(caller), errMsg);
    }

    private void onlyOwner() {
        checkCallerOrThrow(Context.getOwner(), "OnlyOwner");
    }

    private void checkService(String _svc) {
        Context.require(NAME.equals(_svc), "InvalidServiceName");
    }

    private BigInteger getNextSn() {
        BigInteger _sn = this.sn.getOrDefault(BigInteger.ZERO);
        _sn = _sn.add(BigInteger.ONE);
        this.sn.set(_sn);
        return _sn;
    }

    private BigInteger getNextReqId() {
        BigInteger _reqId = this.reqId.getOrDefault(BigInteger.ZERO);
        _reqId = _reqId.add(BigInteger.ONE);
        this.reqId.set(_reqId);
        return _reqId;
    }

    private void cleanupCallRequest(BigInteger sn) {
        requests.set(sn, null);
    }

    @Override
    @Payable
    @External
    public BigInteger sendCallMessage(String _to, byte[] _data, @Optional byte[] _rollback) {
        Address caller = Context.getCaller();
        // check if caller is a contract or rollback data is null in case of EOA
        Context.require(caller.isContract() || _rollback == null, "RollbackNotPossible");

        // check size of payloads to avoid abusing
        Context.require(_data.length <= MAX_DATA_SIZE, "MaxDataSizeExceeded");
        Context.require(_rollback == null || _rollback.length <= MAX_ROLLBACK_SIZE, "MaxRollbackSizeExceeded");

        boolean needResponse = _rollback != null;
        ProtocolPrefixNetworkAddress dst = ProtocolPrefixNetworkAddress.valueOf(_to);
        BigInteger value = Context.getValue();
        BigInteger requiredFee = BigInteger.ZERO;
        List<String> protocols = dst.protocolsList();
        Map<String, BigInteger> fees = new HashMap<>();
        for (String protocol : protocols) {
            requiredFee = requiredFee.add(getFee(protocol, dst.net(), needResponse));
            fees.put(protocol, requiredFee);
        }

        BigInteger protocolFee = getProtocolFee();
        requiredFee = requiredFee.add(protocolFee);
        Context.require(value.compareTo(requiredFee) >= 0, "InsufficientFee");
        BigInteger tip = value.subtract(requiredFee).divide(BigInteger.valueOf(protocols.size()));
        // handle protocol fee
        Address feeHandler = getProtocolFeeHandler();
        if (feeHandler != null && protocolFee.signum() > 0) {
            // we trust fee handler, it should just accept the protocol fee and return
            // assume that no reentrant cases occur here
            Context.transfer(feeHandler, protocolFee);
        }

        BigInteger sn = getNextSn();
        if (needResponse) {
            CallRequest req = new CallRequest(caller, _to, _rollback);
            requests.set(sn, req);
        }
        CSMessageRequest msgReq = new CSMessageRequest(caller.toString(), _to, sn, needResponse, _data);
        for (String protocol : protocols) {
            BigInteger fee = fees.get(protocol).add(tip);
             sendBTPMessage(protocol, fee, dst.net(), CSMessage.REQUEST,
                needResponse ? sn : BigInteger.ZERO, msgReq.toBytes());
        }

        CallMessageSent(caller, dst.toString(), sn);
        return sn;
    }

    @Override
    @External
    public void executeCall(BigInteger _reqId) {
        CSMessageRequest req = proxyReqs.get(_reqId);
        Context.require(req != null, "InvalidRequestId");
        // cleanup
        proxyReqs.set(_reqId, null);

        CSMessageResponse msgRes = null;
        try {
            CallServiceReceiver proxy = new DAppProxy(Address.fromString(req.getTo()));
            proxy.handleCallMessage(req.getFrom(), req.getData());
            msgRes = new CSMessageResponse(req.getSn(), CSMessageResponse.SUCCESS, "");
        } catch (UserRevertedException e) {
            int code = e.getCode();
            String msg = "UserReverted(" + code + ")";
            msgRes = new CSMessageResponse(req.getSn(), code == 0 ? CSMessageResponse.FAILURE : code, msg);
        } catch (IllegalArgumentException | RevertedException e) {
            msgRes = new CSMessageResponse(req.getSn(), CSMessageResponse.FAILURE, e.toString());
        } finally {
            if (msgRes == null) {
                msgRes = new CSMessageResponse(req.getSn(), CSMessageResponse.FAILURE, "UnknownFailure");
            }
            CallExecuted(_reqId, msgRes.getCode(), msgRes.getMsg());
            // send response only when there was a rollback
            if (req.needRollback()) {
                BigInteger sn = req.getSn().negate();
                ProtocolPrefixNetworkAddress from = ProtocolPrefixNetworkAddress.valueOf(req.getFrom());
                for (String protocol : from.protocolsList()) {
                    sendBTPMessage(protocol, BigInteger.ZERO, from.net(), CSMessage.RESPONSE, sn, msgRes.toBytes());
                }

            }
        }
    }

    @Override
    @External
    public void executeRollback(BigInteger _sn) {
        CallRequest req = requests.get(_sn);
        Context.require(req != null, "InvalidSerialNum");
        Context.require(req.enabled(), "RollbackNotEnabled");
        cleanupCallRequest(_sn);
        ProtocolPrefixNetworkAddress to = ProtocolPrefixNetworkAddress.valueOf(req.getTo());
        List<String> protocols = to.protocolsList();
        ProtocolPrefixNetworkAddress xCallProtocolAddress = new ProtocolPrefixNetworkAddress(protocols, networkAddress.get());
        CSMessageResponse msgRes = null;
        try {
            CallServiceReceiver proxy = new DAppProxy(req.getFrom());
            proxy.handleCallMessage(xCallProtocolAddress.toString(), req.getRollback());
            msgRes = new CSMessageResponse(_sn, CSMessageResponse.SUCCESS, "");
        } catch (UserRevertedException e) {
            int code = e.getCode();
            String msg = "UserReverted(" + code + ")";
            msgRes = new CSMessageResponse(_sn, code == 0 ? CSMessageResponse.FAILURE : code, msg);
        } catch (IllegalArgumentException | RevertedException e) {
            msgRes = new CSMessageResponse(_sn, CSMessageResponse.FAILURE, e.toString());
        } finally {
            if (msgRes == null) {
                msgRes = new CSMessageResponse(_sn, CSMessageResponse.FAILURE, "UnknownFailure");
            }
            RollbackExecuted(_sn, msgRes.getCode(), msgRes.getMsg());
        }
    }

    @Override
    @EventLog(indexed=3)
    public void CallMessage(String _from, String _to, BigInteger _sn, BigInteger _reqId) {}

    @Override
    @EventLog(indexed=1)
    public void CallExecuted(BigInteger _reqId, int _code, String _msg) {}

    @Override
    @EventLog(indexed=1)
    public void ResponseMessage(BigInteger _sn, int _code, String _msg) {}

    @Override
    @EventLog(indexed=1)
    public void RollbackMessage(BigInteger _sn) {}

    @Override
    @EventLog(indexed=1)
    public void RollbackExecuted(BigInteger _sn, int _code, String _msg) {}

    @Override
    @EventLog(indexed=3)
    public void CallMessageSent(Address _from, String _to, BigInteger _sn) {}

    /* ========== Interfaces with BMC ========== */
    @Override
    @External
    public void handleBTPMessage(String _from, String _svc, BigInteger _sn, byte[] _msg) {
        String protocol = protocols.get(Context.getCaller());
        Context.require(protocol != null);
        checkService(_svc);

        CSMessage msg = CSMessage.fromBytes(_msg);
        switch (msg.getType()) {
            case CSMessage.REQUEST:
                handleRequest(protocol,_from, _sn, msg.getData());
                break;
            case CSMessage.RESPONSE:
                handleResponse(protocol, _from, _sn, msg.getData());
                break;
            default:
                Context.revert("UnknownMsgType(" + msg.getType() + ")");
        }
    }

    @Override
    @External
    public void handleBTPError(String _src, String _svc, BigInteger _sn, long _code, String _msg) {
        String protocol = protocols.get(Context.getCaller());
        Context.require(protocol != null);
        checkService(_svc);

        String errMsg = "BTPError{code=" + _code + ", msg=" + _msg + "}";
        CSMessageResponse res = new CSMessageResponse(_sn, CSMessageResponse.BTP_ERROR, errMsg);
        handleResponse(protocol, _src, _sn, res.toBytes());
    }
    /* ========================================= */

    private BigInteger sendBTPMessage(String protocol, BigInteger value, String netTo, int msgType, BigInteger sn, byte[] data) {
        CSMessage msg = new CSMessage(msgType, data);
        ConnectionScoreInterface connection = new ConnectionScoreInterface(connections.get(protocol));
        return connection.sendMessage(value, netTo, NAME, sn, msg.toBytes());
    }

    private void handleRequest(String protocol, String netFrom, BigInteger sn, byte[] data) {
        CSMessageRequest msgReq = CSMessageRequest.fromBytes(data);
        ProtocolPrefixNetworkAddress to = ProtocolPrefixNetworkAddress.valueOf(msgReq.getTo());
        List<String> protocols = to.protocolsList();
        if (protocols.size() > 1) {
            byte[] dataHash = Context.hash("sha256", data);
            proxyRequestProtocols.at(protocol).set(msgReq.getSn(), dataHash);
            byte[][] hashes = new byte[protocols.size()][];
            for (int i = 0; i < protocols.size(); i++) {
                byte[] hash =  proxyRequestProtocols.at(protocols.get(i)).get(msgReq.getSn());
                if (hash == null) {
                    return;
                }

                hashes[i] = hash;
            }

            for (byte[] bs : hashes) {
                Context.require(Arrays.equals(dataHash, bs), "malformed data between connections");
            }
        }

        ProtocolPrefixNetworkAddress from = new ProtocolPrefixNetworkAddress(protocols, netFrom, msgReq.getFrom());

        BigInteger reqId = getNextReqId();
        CSMessageRequest req = new CSMessageRequest(from.toString(), to.account(), msgReq.getSn(), msgReq.needRollback(), msgReq.getData());
        proxyReqs.set(reqId, req);

        // emit event to notify the user
        CallMessage(from.toString(), to.account(), msgReq.getSn(), reqId);

    }

    private void handleResponse(String protocol, String netFrom, BigInteger sn, byte[] data) {
        CSMessageResponse msgRes = CSMessageResponse.fromBytes(data);
        BigInteger resSn = msgRes.getSn();
        CallRequest req = requests.get(resSn);
        if (req == null) {
            Context.println("handleResponse: no request for " + resSn);
            return; // just ignore
        }

        ProtocolPrefixNetworkAddress to = ProtocolPrefixNetworkAddress.valueOf(req.getTo());
        List<String> protocols = to.protocolsList();
        if (protocols.size() > 1) {
            byte[] dataHash = Context.hash("sha256", data);
            responseProtocols.at(protocol).set(resSn, dataHash);
            byte[][] hashes = new byte[protocols.size()][];
            for (int i = 0; i < protocols.size(); i++) {
                byte[] hash =  responseProtocols.at(protocols.get(i)).get(resSn);
                if (hash == null) {
                    return;
                }

                hashes[i] = hash;
            }

            for (byte[] bs : hashes) {
                Context.require(Arrays.equals(dataHash, bs), "malformed data between connections");
            }
        }

        String errMsg = msgRes.getMsg();
        ResponseMessage(resSn, msgRes.getCode(), errMsg != null ? errMsg : "");
        switch (msgRes.getCode()) {
            case CSMessageResponse.SUCCESS:
                cleanupCallRequest(resSn);
                break;
            case CSMessageResponse.FAILURE:
            case CSMessageResponse.BTP_ERROR:
            default:
                // emit rollback event
                Context.require(req.getRollback() != null, "NoRollbackData");
                req.setEnabled();
                requests.set(resSn, req);
                RollbackMessage(resSn);
        }
    }

    // @External(readonly=true)
    // public Address protocols() {
    //     for in
    //     return admin.getOrDefault(Context.getOwner());
    // }

    @External
    public void addProtocol(Address address, String name) {
        onlyOwner();
        protocols.set(address, name);
        connections.set(name, address);
        availableProtocols.add(name);
    }

    @External(readonly=true)
    public Address admin() {
        return admin.getOrDefault(Context.getOwner());
    }

    @External
    public void setAdmin(Address _address) {
        onlyOwner();
        admin.set(_address);
    }

    @External
    public void setProtocolFeeHandler(@Optional Address _addr) {
        checkCallerOrThrow(admin(), "OnlyAdmin");
        feeHandler.set(_addr);
        if (_addr != null) {
            var accruedFees = Context.getBalance(Context.getAddress());
            if (accruedFees.signum() > 0) {
                Context.transfer(_addr, accruedFees);
            }
        }
    }

    @External(readonly=true)
    public Address getProtocolFeeHandler() {
        return feeHandler.get();
    }

    @External
    public void setProtocolFee(BigInteger _value) {
        checkCallerOrThrow(admin(), "OnlyAdmin");
        Context.require(_value.signum() >= 0, "ValueShouldBePositive");
        protocolFee.set(_value);
    }

    @External(readonly=true)
    public BigInteger getProtocolFee() {
        return protocolFee.getOrDefault(BigInteger.ZERO);
    }

    @External(readonly=true)
    public BigInteger getFee(String protocol, String _net, boolean _rollback) {
        if (_net.isEmpty() || _net.indexOf('/') != -1 || _net.indexOf(':') != -1) {
            Context.revert("InvalidNetworkAddress");
        }
        Connection connection = new ConnectionScoreInterface(connections.get(protocol));
        var relayFee = connection.getFee(_net, _rollback);
        return getProtocolFee().add(relayFee);
    }
}
