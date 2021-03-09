# milenage

[![Hex.pm version](https://img.shields.io/hexpm/v/milenage.svg)](https://hex.pm/packages/milenage)

A MILENAGE algorithm implementation in Erlang/OTP.

# Usage

```erlang
% Initialize with K, OP or OPc, RAND, SQN, AMF. 
Mil = milenage:new(
    opc, 
    <<16#00, 16#11, 16#22, 16#33, 16#44, 16#55, 16#66, 16#77, 16#88, 16#99, 16#aa, 16#bb, 16#cc, 16#dd, 16#ee, 16#ff>>,
    <<16#62, 16#e7, 16#5b, 16#8d, 16#6f, 16#a5, 16#bf, 16#46, 16#ec, 16#87, 16#a9, 16#27, 16#6f, 16#9d, 16#f5, 16#4d>>,
    <<16#00, 16#11, 16#22, 16#33, 16#44, 16#55, 16#66, 16#77, 16#88, 16#99, 16#aa, 16#bb, 16#cc, 16#dd, 16#ee, 16#ff>>,
    1,
    16#8000
    )

% Perform the functions you want to retrieve values like this.
MACA = milenage:f1(Mil, 1, 16#8000)
{RES, CK, IK, AK} = milenage:f2345(Mil)

% Retrieve 5G RES* by compute_res_star().
RESStar = milenage:compute_res_star(Mil, "001", "01")

% This returns a new #milenage with all the possible values set.
Mil2 = milenage:compute_all(M)
AK = Mil2 #milenage.ak
```

# Build

```
rebar3 compile
```

# TODOs

- [ ] Validations
- [ ] CI tests
