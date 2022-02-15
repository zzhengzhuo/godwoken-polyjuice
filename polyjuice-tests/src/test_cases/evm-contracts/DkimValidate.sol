pragma solidity >=0.4.0;

contract DkimValidate {
    function validate(
        bytes memory email,
        uint32 e,
        bytes memory n
    ) public returns (bytes memory output) {
        bytes memory input = abi.encodePacked(
            uint32(email.length),
            email,
            e,
            uint32(n.length),
            n
        );
        uint32 len = uint32(input.length);
        // bytes memory output;
        // uint32 output_len = 1;
        assembly {
            output := mload(0x40)
            
            let ret := call(not(0), 0xf5, 0x0, input, len, 0x40, 0x20)
            if ret{
                return (ret,4)
            }
        }
        // (
        //     uint32 ret,
        //     bytes memory from_header,
        //     bytes memory subject_header
        // ) = abi.decode(output, (uint32, bytes, bytes));
        // return output_len;
    } 
}
