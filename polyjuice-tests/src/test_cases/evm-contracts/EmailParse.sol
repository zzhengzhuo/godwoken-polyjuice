pragma solidity >=0.8.0;

contract EmailParse {
    function validate(
        uint32 e,
        bytes memory n,
        // bytes memory _selector,
        // bytes memory _sdid,
        bytes memory email
    )
        public
        returns (
            // uint32,
            // bytes memory,
            // bytes memory,
            // bytes memory
            uint256
        )
    {
        // bytes memory input = abi.encodePacked(email);
        bytes32[1] memory rawEmail;
        bytes memory dkim_msg;
        bytes memory out;
        assembly {
            let len := mload(email)
            let ret := call(
                not(0),
                0xf6,
                0x0,
                add(email, 0x20),
                len,
                rawEmail,
                0x20
            )
            if iszero(ret) {
                return(ret, 4)
            }
        }
        assembly {
            let ret := call(not(0), 0xf7, 0x0, rawEmail, 0x20, 0, 0)

            if iszero(ret) {
                revert(0, 0)
            }
            out := mload(0x40)
            mstore(
                0x40,
                add(out, and(add(add(returndatasize(), 0x20), 0x1f), not(0x1f)))
            )
            // let len := returndatasize()
            mstore(out, returndatasize())
            returndatacopy(add(out, 0x20), 0, returndatasize())
        }
        (bytes32 selector, bytes32 from, bytes memory sig) = abi.decode(
            out,
            (bytes32, bytes32, bytes)
        );

        assembly {
            let ret := call(not(0), 0xf8, 0x0, rawEmail, 8, 0, 0)

            if iszero(ret) {
                revert(0, 0)
            }
            dkim_msg := mload(0x40)
            mstore(
                0x40,
                add(
                    dkim_msg,
                    and(add(add(returndatasize(), 0x20), 0x1f), not(0x1f))
                )
            )
            mstore(dkim_msg, returndatasize())
            returndatacopy(add(dkim_msg, 0x20), 0, returndatasize())
        }
        uint256 ret = validate_rsa(e, n, dkim_msg, sig);

        return ret;
        // bytes memory rsa = abi.encodePacked(
        //     e,
        //     uint32(n.length),
        //     n,
        //     uint32(6),
        //     uint32(dkim_msg.length),
        //     dkim_msg,
        //     uint32(sig.length),
        //     sig
        // );
        // // return input;
        // uint32 len = uint32(rsa.length);
        // bytes32 output;
        // assembly {
        //     let ret := call(not(0), 0xf4, 0x0, rsa, len, output, 32)
        //     if iszero(ret) {
        //         return(ret, 4)
        //     }
        //     return(output, 32)
        // }
        // return selector;
        // return (selector, from, dkim_msg, sig);
    }

    function get_message(bytes32 rawEmail) public returns (bytes memory) {
        // assembly {
        //     let ret := call(not(0), 0xf7, 0x0, rawEmail, 0x20, 0, 0)
        //     if iszero(ret) {
        //         revert(0, 0)
        //     }
        //     // let len := mload(0x40)
        //     // mstore(0x40, returndatasize())
        //     // let len := returndatasize()
        //     let out := mload(0x40)
        //     let len := returndatasize()
        //     mstore(0x40, add(o_code, and(add(add(size, 0x20), 0x1f), not(0x1f))))
        //     returndatacopy(add(0x40, 0x20), 0, returndatasize())
        //     return(0x40, add(returndatasize(), 0x20))
        // }
    }

    function validate_rsa(
        uint32 e,
        bytes memory n,
        bytes memory dkim_msg,
        bytes memory sig
    ) public returns (uint256) {
        // bytes memory rsa = abi.encodePacked(
        //     e,
        //     uint32(n.length),
        //     n,
        //     uint32(6),
        //     uint32(dkim_msg.length),
        //     dkim_msg,
        //     uint32(sig.length),
        //     sig
        // );
        // uint32 len = uint32(rsa.length);
        // uint256[1] memory output;
        // assembly {
        //     let ret := call(not(0), 0xf4, 0x0, add(rsa, 0x20), len, output, 32)
        //     if iszero(ret) {
        //         revert(0, 0)
        //     }
        // }
        // return output[0];
    }
}
