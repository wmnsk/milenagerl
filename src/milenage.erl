-module(milenage).

-export([
    new/6, compute_opc/2, set_opc/3, compute_all/1,
    f1/3, f1star/3, f2345/1, f5star/1, compute_res_star/3
]).

-include_lib("include/milenage.hrl").

-define(VALIDATE_NEW(K, OP, RAND, SQN, AMF),
    is_binary(K) and is_binary(OP) and is_binary(RAND) and is_integer(SQN) and is_integer(AMF)).

%% Initializes MILENAGE with OP or OPc.
new(op, K, OP, RAND, SQN, AMF) when ?VALIDATE_NEW(K, OP, RAND, SQN, AMF) ->
    M = #milenage{k = K, op = OP, rand = RAND, sqn = SQN, amf = AMF},
    set_opc(M, K, OP);
new(opc, K, OPc, RAND, SQN, AMF) when ?VALIDATE_NEW(K, OPc, RAND, SQN, AMF) ->
    #milenage{k = K, opc = OPc, rand = RAND, sqn = SQN, amf = AMF};
new(_, _, _, _, _, _) ->
    #milenage{}.

%% Performs f1 which is the network authentication function that computes network
%% authentication code MAC-A from key K, random challenge RAND, sequence number 
%% SQN and authentication management field AMF.
f1(M, SQN, AMF) ->
    <<MACA:64, _/binary>> = f1base(M, SQN, AMF),
    <<MACA:64>>.

%% Performs f1star which is the re-synchronisation message authentication
%% function that computes resynch authentication code MAC-S from key K, random
%% challenge RAND, sequence number SQN and authentication management field AMF.
%%
%% Note that the AMF value should be zero to be compliant with the specification
%% TS 33.102 6.3.3 (This function just computes with the given value).
f1star(M, SQN, AMF) ->
    <<_:64, MACS:64>> = f1base(M, SQN, AMF),
    <<MACS:64>>.

%% Performs the calcurations that are common in f1/1 and f1star/1.
f1base(#milenage{k = K, opc = OPc, rand = RAND}, SQN, AMF) ->
    <<Rx8F:64, Rx07:64>> = crypto:exor(<<SQN:48, AMF:16, SQN:48, AMF:16>>, OPc),
    T = encrypt(K, crypto:exor(RAND, OPc)),
    O = encrypt(K, crypto:exor(<<Rx07:64, Rx8F:64>>, T)),
    crypto:exor(O, OPc).

%% Performas the functions f2, f3, f4, f5 at a time which take key K and random
%% challenge RAND, and returns response RES, confidentiality key CK, integrity key
%% IK and anonymity key AK.
f2345(#milenage{k = K, opc = OPc, rand = RAND}) ->
    Temp = encrypt(K, crypto:exor(RAND, OPc)),
    R1 = crypto:exor(Temp, OPc),
    <<_:120, R1x:8>> = R1,
    X1 = R1x bxor 1,
    <<AK:6/binary, _:2/binary, RES:8/binary>> = crypto:exor(encrypt(K, <<R1:15/binary, X1>>), OPc),

    <<R3xCF:32, R3x0B:96>> = crypto:exor(Temp, OPc),
    R3 = <<R3x0B:96, R3xCF:32>>,
    <<_:120, R3x:8>> = R3,
    X3 = R3x bxor 2,
    CK = crypto:exor(encrypt(K, <<R3:15/binary, X3>>), OPc),

    <<R5x8F:64, R5x07:64>> = crypto:exor(Temp, OPc),
    R5 = <<R5x07:64, R5x8F:64>>,
    <<_:120, R5x:8>> = R5,
    X5 = R5x bxor 4,
    IK = crypto:exor(encrypt(K, <<R5:15/binary, X5>>), OPc),

    {RES, CK, IK, AK}.

%% Performs f5 star which is the anonymity key derivation function for the
%% re-synchronisation message. It takes key K and random challenge RAND, and
%% returns resynch anonymity key AK.
f5star(#milenage{k = K, opc = OPc, rand = RAND}) ->
    Temp = encrypt(K, crypto:exor(RAND, OPc)),
    <<Rx4F:96, Rx03:32>> = crypto:exor(Temp, OPc),
    R = <<Rx03:32, Rx4F:96>>,
    <<_:120, Rx:8>> = R,
    X = Rx bxor 8,
    <<AKS:6/binary, _:10/binary>> = crypto:exor(encrypt(K, <<R:15/binary, X>>), OPc),
    crypto:exor(AKS, <<0:48>>).

%% Performs all the milenage functions and returns the milenage record
%% with the computed values set.
compute_all(#milenage{sqn = SQN, amf = AMF} = M) ->
    MACA = f1(M, SQN, AMF),
    MACS = f1star(M, SQN, 0),
    {RES, CK, IK, AK} = f2345(M),
    AKS = f5star(M),
    M#milenage{mac_a = MACA, mac_s = MACS, res = RES, ck = CK, ik = IK, ak = AK, aks = AKS}.

%% Performs RES* derivation function which is defined in A.4 RES* and XRES*
%% derivation function, TS 33.501.
compute_res_star(#milenage{rand = RAND, res = Res, ck = CK, ik = IK}, MCC, MNC) when length(MCC) =:= 3 ->
    N = case length(MNC) of
        2 -> "0" ++ MNC;
        3 -> MNC;
        _ -> undefined
    end,

    SNN = list_to_binary(lists:flatten(io_lib:format("5G:mnc~s.mcc~s.3gppnetwork.org", [N, MCC]))),
    B = <<16#6b, SNN:32/binary, 32:16, RAND:16/binary, 16:16, Res:8/binary, 8:16>>,

    <<_:128, Out/binary>> = crypto:mac(hmac, sha256, <<CK:16/binary, IK:16/binary>>, B),
    Out.

%% Computes OPc value from K and OP.
compute_opc(K, OP) ->
    crypto:exor(encrypt(OP, K), OP).

%% Returns milenage with OPc set. This is called automatically when using new/6
%% with 'op' as the first parameter.
set_opc(M, K, OP) ->
    OPC = compute_opc(K, OP),
    M#milenage{opc=OPC}.

%% Performs AES/128/ECB encryption with the key and text given as binary.
encrypt(Key, Plain) ->
    crypto:crypto_one_time(aes_128_ecb, Key, Plain, [{encrypt, true}, {padding, zero}]).
