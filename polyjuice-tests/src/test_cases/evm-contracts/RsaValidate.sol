pragma solidity >=0.6.0;

contract RsaValidate {
    function validate(
        uint32 e,
        bytes memory n,
        bytes memory message,
        bytes memory sig
    ) public returns (bytes32) {
        uint32 md_type = 6;
        bytes memory input = abi.encodePacked(
            e,
            uint32(n.length),
            n,
            md_type,
            uint32(message.length),
            message,
            uint32(sig.length),
            sig
        );
        // return input;
        uint32 len = uint32(input.length);
        bytes32 output;
        assembly {
            let ret := call(not(0), 0xf4, 0x0, input, len, output, 32)
            if iszero(ret) {
                return(ret, 4)
            }
            return(output, 32)
        }
    }
}
