-module(milenage).

-include_lib("eunit/include/eunit.hrl").

-export([new/6, compute_opc/2, set_opc/3, f1/3, f1star/3, f2345/1, f5star/1, compute_all/1]).

-define(VALIDATE_NEW(K, OP, RAND, SQN, AMF),
    is_binary(K) and is_binary(OP) and is_binary(RAND) and is_integer(SQN) and is_integer(AMF)).

%% A set of parameters used/generated in MILENAGE algorithm.
-record(milenage,
    {
        %% AK is a 48-bit anonymity key that is the output of either of the functions f5.
        ak = <<0:48>>,
        %% AKS is a 48-bit anonymity key that is the output of either of the functions f5*.
        aks = <<0:48>>,
        %% AMF is a 16-bit authentication management field that is an input to the functions f1 and f1*.
        amf = 16#0000,
        %% CK is a 128-bit confidentiality key that is the output of the function f3.
        ck = <<0:128>>,
        %% IK is a 128-bit integrity key that is the output of the function f4.
        ik = <<0:128>>,
        %% K is a 128-bit subscriber key that is an input to the functions f1, f1*, f2, f3, f4, f5 and f5*.
        k,
        %% MACA is a 64-bit network authentication code that is the output of the function f1.
        mac_a = <<0:64>>,
        %% MACS is a 64-bit resynchronisation authentication code that is the output of the function f1*.
        mac_s = <<0:64>>,
        %% OP is a 128-bit Operator Variant Algorithm Configuration Field that is a component of the
    	%% functions f1, f1*, f2, f3, f4, f5 and f5*.
        op = <<0:128>>,
        %% OPc is a 128-bit value derived from OP and K and used within the computation of the functions.
        opc = <<0:128>>,
        %% RAND is a 128-bit random challenge that is an input to the functions f1, f1*, f2, f3, f4, f5 and f5*.
        rand,
        %% RES is a 64-bit signed response that is the output of the function f2.
        res = <<0:64>>,
        %% RES_STAR or RES* is a 128-bit response that is used in 5G.
        res_star = <<0:128>>,
        %% SQN is a 48-bit sequence number that is an input to either of the functions f1 and f1*.
    	%% (For f1* this input is more precisely called SQNMS.)
        sqn
    }).

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
f1base(M, SQN, AMF) ->
    K = M#milenage.k,
    OPc = M#milenage.opc,

    <<Rx8F:64, Rx07:64>> = crypto:exor(<<SQN:48, AMF:16, SQN:48, AMF:16>>, OPc),

    T = encrypt(K, crypto:exor(M#milenage.rand, OPc)),
    O = encrypt(K, crypto:exor(<<Rx07:64, Rx8F:64>>, T)),
    crypto:exor(O, OPc).

%% Performas the functions f2, f3, f4, f5 at a time which take key K and random
%% challenge RAND, and returns response RES, confidentiality key CK, integrity key
%% IK and anonymity key AK.
f2345(M) ->
    K = M#milenage.k,
    OPc = M#milenage.opc,

    Temp = encrypt(K, crypto:exor(M#milenage.rand, OPc)),
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
f5star(M) ->
    K = M#milenage.k,
    OPc = M#milenage.opc,

    Temp = encrypt(K, crypto:exor(M#milenage.rand, OPc)),
    <<Rx4F:96, Rx03:32>> = crypto:exor(Temp, OPc),
    R = <<Rx03:32, Rx4F:96>>,
    <<_:120, Rx:8>> = R,
    X = Rx bxor 8,
    <<AKS:6/binary, _:10/binary>> = crypto:exor(encrypt(K, <<R:15/binary, X>>), OPc),
    crypto:exor(AKS, <<0:48>>).

%% Performs all the milenage functions and returns the milenage record
%% with the computed values set.
compute_all(M) ->
    MACA = f1(M, M#milenage.sqn, M#milenage.amf),
    MACS = f1star(M, M#milenage.sqn, 0),
    {RES, CK, IK, AK} = f2345(M),
    AKS = f5star(M),
    M#milenage{mac_a=MACA, mac_s=MACS, res=RES, ck=CK, ik=IK, ak=AK, aks=AKS}.

%% Computes OPc value from K and OP.
compute_opc(K, OP) ->
    crypto:exor(encrypt(K, K), OP).

%% Returns milenage with OPc set. This is called automatically when using new/6
%% with 'op' as the first parameter.
set_opc(M, K, OP) ->
    OPC = compute_opc(K, OP),
    M#milenage{opc=OPC}.

%% Performs AES/128/ECB encryption with the key and text given as binary.
encrypt(Key, Plain) ->
    crypto:crypto_one_time(aes_128_ecb, Key, Plain, [{encrypt, true}, {padding, zero}]).

-ifdef(EUNIT).
-define(AK,       <<16#de, 16#65, 16#6c, 16#8b, 16#0b, 16#ce>>).
-define(AKS,      <<16#b9, 16#ac, 16#50, 16#c4, 16#8a, 16#83>>).
-define(AMF,      16#8000).
-define(CK,       <<16#b3, 16#79, 16#87, 16#4b, 16#3d, 16#18, 16#3d, 16#2a, 16#21, 16#29, 16#1d, 16#43, 16#9e, 16#77, 16#61, 16#e1>>).
-define(IK,       <<16#f4, 16#70, 16#6f, 16#66, 16#62, 16#9c, 16#f7, 16#dd, 16#f8, 16#81, 16#d8, 16#00, 16#25, 16#bf, 16#12, 16#55>>).
-define(K,        <<16#00, 16#11, 16#22, 16#33, 16#44, 16#55, 16#66, 16#77, 16#88, 16#99, 16#aa, 16#bb, 16#cc, 16#dd, 16#ee, 16#ff>>).
-define(MACA,     <<16#4a, 16#f3, 16#0b, 16#82, 16#a8, 16#53, 16#11, 16#15>>).
-define(MACS,     <<16#cd, 16#f7, 16#46, 16#73, 16#bc, 16#86, 16#e7, 16#ab>>).
-define(OP,       <<16#00, 16#11, 16#22, 16#33, 16#44, 16#55, 16#66, 16#77, 16#88, 16#99, 16#aa, 16#bb, 16#cc, 16#dd, 16#ee, 16#ff>>).
-define(OPc,      <<16#62, 16#e7, 16#5b, 16#8d, 16#6f, 16#a5, 16#bf, 16#46, 16#ec, 16#87, 16#a9, 16#27, 16#6f, 16#9d, 16#f5, 16#4d>>).
-define(RAND,     <<16#00, 16#11, 16#22, 16#33, 16#44, 16#55, 16#66, 16#77, 16#88, 16#99, 16#aa, 16#bb, 16#cc, 16#dd, 16#ee, 16#ff>>).
-define(RES,      <<16#70, 16#0e, 16#b2, 16#30, 16#0b, 16#2c, 16#47, 16#99>>).
-define(RES_STAR, <<16#31, 16#b6, 16#d9, 16#38, 16#a5, 16#29, 16#0c, 16#cc, 16#65, 16#bc, 16#82, 16#9f, 16#98, 16#20, 16#a8, 16#d9>>).
-define(SQN,      1).
-endif.

new_test() ->
    [
        ?assertEqual(new(op, ?K, ?OP, <<0:128>>, ?SQN, ?AMF),
            #milenage{
                ak = <<0:48>>, aks = <<0:48>>, amf=16#8000, ck = <<0:128>>,
                ik = <<0:128>>, k = ?K, mac_a = <<0:64>>, mac_s = <<0:64>>,
                op = ?OP, opc = ?OPc, rand = <<0:128>>, res = <<0:64>>,
                res_star = <<0:128>>, sqn = 1
            }),
        ?assertEqual(new(opc, ?K, ?OPc, <<0:128>>, ?SQN, ?AMF),
            #milenage{
                ak = <<0:48>>, aks = <<0:48>>, amf=16#8000, ck = <<0:128>>,
                ik = <<0:128>>, k = ?K, mac_a = <<0:64>>, mac_s = <<0:64>>,
                op = <<0:128>>, opc = ?OPc, rand = <<0:128>>, res = <<0:64>>,
                res_star = <<0:128>>, sqn = 1
            }),
       ?assertEqual(new(op, 1, ?OP, <<0:128>>, ?SQN, ?AMF), #milenage{}), % Unexpected K
       ?assertEqual(new(op, ?K, 1, <<0:128>>, ?SQN, ?AMF), #milenage{}), % Unexpected OP
       ?assertEqual(new(op, ?K, ?OP, 1, ?SQN, ?AMF), #milenage{}), % Unexpected RAND
       ?assertEqual(new(op, ?K, ?OP, 1, <<0:128>>, 16#8000), #milenage{}), % Unexpected SQN
       ?assertEqual(new(op, ?K, ?OP, 1, 1, <<0:128>>), #milenage{}), % Unexpected AMF
       ?assertEqual(new(opc, 1, ?OPc, <<0:128>>, ?SQN, ?AMF), #milenage{}), % Unexpected K
       ?assertEqual(new(opc, ?K, 1, <<0:128>>, ?SQN, ?AMF), #milenage{}), % Unexpected OPc
       ?assertEqual(new(opc, ?K, ?OPc, 1, ?SQN, ?AMF), #milenage{}), % Unexpected RAND
       ?assertEqual(new(opc, ?K, ?OPc, 1, <<0:128>>, 16#8000), #milenage{}), % Unexpected SQN
       ?assertEqual(new(opc, ?K, ?OPc, 1, 1, <<0:128>>), #milenage{}) % Unexpected AMF
    ].

compute_opc_test() ->
    [
        ?assertEqual(compute_opc(?K, ?OP), ?OPc)
    ].

f1_test() ->
    [
        ?assertEqual(f1(new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF), ?SQN, ?AMF), ?MACA)
    ].

f1star_test() ->
    [ % TS 33.102 6.3.3: AMF should be zero when computing f1star.
        ?assertEqual(f1star(new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF), ?SQN, 0), ?MACS)
    ].

f2345_test() ->
    [
        ?assertEqual(f2345(new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF)), {?RES, ?CK, ?IK, ?AK})
    ].

f5star_test() ->
    [
        ?assertEqual(f5star(new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF)), ?AKS)
    ].

compute_all_test() ->
    [
        ?assertEqual(compute_all(new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF)),
            #milenage{
                ak = ?AK,
                aks = ?AKS,
                amf = 16#8000,
                ck = ?CK,
                ik = ?IK,
                k = ?K,
                mac_a = ?MACA,
                mac_s = ?MACS,
                op = ?OP,
                opc = ?OPc,
                rand = ?RAND,
                res = ?RES,
                res_star = ?RES_STAR,
                sqn = 1
            }
        )
    ].
