set -x
set -e

SCRIPT_DIR=$(realpath $(dirname $0))
PROJECT_ROOT=$(dirname $(dirname $SCRIPT_DIR))
TESTS_DIR=$PROJECT_ROOT/polyjuice-tests
DEPS_DIR=$PROJECT_ROOT/integration-test
GODWOKEN_DIR=$DEPS_DIR/godwoken

mkdir -p $DEPS_DIR
if [ -d "$GODWOKEN_DIR" ]
then
    echo "godwoken project already exists"
else
    git clone -b develop https://github.com/zzhengzhuo/godwoken.git $GODWOKEN_DIR
fi
cd $GODWOKEN_DIR
git checkout polyjuice-test # https://github.com/nervosnetwork/godwoken/commits/1dc4092
git submodule update --init --recursive --depth=1

cd $PROJECT_ROOT
git submodule update --init --recursive --depth=1
make all-via-docker
make patch-generator && make patch-generator_log

# fetch godwoken-scripts from godwoken-prebuilds image,
# including meta-contract and sudt-contract
GW_SCRIPTS_DIR=$PROJECT_ROOT/build
docker pull nervos/godwoken-prebuilds:latest
mkdir -p $GW_SCRIPTS_DIR && echo "Create dir"
docker run --rm -v $GW_SCRIPTS_DIR:/build-dir \
  nervos/godwoken-prebuilds:latest \
  cp -r /scripts/godwoken-scripts /build-dir \
  && echo "Copy godwoken-scripts"

cd $TESTS_DIR
export RUST_BACKTRACE=full
# cargo test --package polyjuice-tests --bin polyjuice-tests -- test_cases::dkim_validate::test_dkim_validate --exact --nocapture
solc src/test_cases/evm-contracts/RsaValidate.sol --abi --bin -o src/test_cases/evm-contracts --overwrite
solc src/test_cases/evm-contracts/DkimValidate.sol --abi --bin -o src/test_cases/evm-contracts --overwrite
solc src/test_cases/evm-contracts/EmailParse.sol --abi --bin -o src/test_cases/evm-contracts --overwrite 

RUST_LOG=debug cargo test -- --nocapture
# cargo bench | egrep -v debug
