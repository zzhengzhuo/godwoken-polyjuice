pragma solidity >=0.4.0;

contract DkimValidate {
    function validate(
        uint32 e,
        bytes memory n,
        bytes memory email
    ) public returns (bytes32[2] memory out) {
        bytes memory input = abi.encodePacked(
            e,
            uint32(n.length),
            n,
            uint32(email.length),
            email
        );
        bytes32[2] memory output;
        assembly {
            let len := mload(input)
            let ret := call(
                not(0),
                0xf5,
                0x0,
                add(input, 0x20),
                len,
                output,
                0x40
            )
            if iszero(ret) {
                return(ret, 4)
            }
        }
        return output;
    }
}
