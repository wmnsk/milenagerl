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
