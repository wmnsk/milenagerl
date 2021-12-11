-module(milenage_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("include/milenage.hrl").

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

new_test_() ->
    [
        ?_assertEqual(milenage:new(op, ?K, ?OP, <<0:128>>, ?SQN, ?AMF),
                     #milenage{
                         ak = <<0:48>>, aks = <<0:48>>, amf=16#8000, ck = <<0:128>>,
                         ik = <<0:128>>, k = ?K, mac_a = <<0:64>>, mac_s = <<0:64>>,
                         op = ?OP, opc = ?OPc, rand = <<0:128>>, res = <<0:64>>,
                         res_star = <<0:128>>, sqn = 1
                    }),
        ?_assertEqual(milenage:new(opc, ?K, ?OPc, <<0:128>>, ?SQN, ?AMF),
                     #milenage{
                         ak = <<0:48>>, aks = <<0:48>>, amf=16#8000, ck = <<0:128>>,
                         ik = <<0:128>>, k = ?K, mac_a = <<0:64>>, mac_s = <<0:64>>,
                         op = <<0:128>>, opc = ?OPc, rand = <<0:128>>, res = <<0:64>>,
                         res_star = <<0:128>>, sqn = 1
                    }),
       ?_assertEqual(milenage:new(op, 1, ?OP, <<0:128>>, ?SQN, ?AMF), #milenage{}), % Unexpected K
       ?_assertEqual(milenage:new(op, ?K, 1, <<0:128>>, ?SQN, ?AMF), #milenage{}), % Unexpected OP
       ?_assertEqual(milenage:new(op, ?K, ?OP, 1, ?SQN, ?AMF), #milenage{}), % Unexpected RAND
       ?_assertEqual(milenage:new(op, ?K, ?OP, 1, <<0:128>>, 16#8000), #milenage{}), % Unexpected SQN
       ?_assertEqual(milenage:new(op, ?K, ?OP, 1, 1, <<0:128>>), #milenage{}), % Unexpected AMF
       ?_assertEqual(milenage:new(opc, 1, ?OPc, <<0:128>>, ?SQN, ?AMF), #milenage{}), % Unexpected K
       ?_assertEqual(milenage:new(opc, ?K, 1, <<0:128>>, ?SQN, ?AMF), #milenage{}), % Unexpected OPc
       ?_assertEqual(milenage:new(opc, ?K, ?OPc, 1, ?SQN, ?AMF), #milenage{}), % Unexpected RAND
       ?_assertEqual(milenage:new(opc, ?K, ?OPc, 1, <<0:128>>, 16#8000), #milenage{}), % Unexpected SQN
       ?_assertEqual(milenage:new(opc, ?K, ?OPc, 1, 1, <<0:128>>), #milenage{}) % Unexpected AMF
    ].

compute_opc_test_() ->
    [
        ?_assertEqual(milenage:compute_opc(?K, ?OP), ?OPc)
    ].

f1_test_() ->
    [
        ?_assertEqual(milenage:f1(milenage:new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF), ?SQN, ?AMF), ?MACA)
    ].

f1star_test_() ->
    [ % TS 33.102 6.3.3: AMF should be zero when computing f1star.
        ?_assertEqual(milenage:f1star(milenage:new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF), ?SQN, 0), ?MACS)
    ].

f2345_test_() ->
    [
        ?_assertEqual(milenage:f2345(milenage:new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF)), {?RES, ?CK, ?IK, ?AK})
    ].

f5star_test_() ->
    [
        ?_assertEqual(milenage:f5star(milenage:new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF)), ?AKS)
    ].

compute_all_test_() ->
    [
        ?_assertEqual(milenage:compute_all(milenage:new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF)),
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
                res_star = <<0:128>>,
                sqn = 1
            }
        )
    ].

compute_res_star_test_() ->
    [
        ?_assertEqual(
            milenage:compute_res_star(
                milenage:compute_all(milenage:new(op, ?K, ?OP, ?RAND, ?SQN, ?AMF)),
                "001", "01"),
            ?RES_STAR)
    ].
