#!/bin/bash

# Deploy the specified contract's `WASM_BIN` to the chain specified by `CHAIN_ID` using the `USER_ADDR` account.
set -eo pipefail

USER_ADDR=${USER_ADDR:-$(wasmd keys show -a admin)}
WASM_BIN="$1"
CHAIN_ID=${CHAIN_ID:-testing}
NODE_URL=${NODE_URL:-127.0.0.1:26657}
LABEL=${LABEL:-sp1-verifier}
COUNT=${COUNT:-0}
ROOT=${ROOT:-.}
WASM_BIN_DIR="$ROOT/target/wasm32-unknown-unknown/release"
TXFLAG="--chain-id ${CHAIN_ID} --gas-prices 0.0025ucosm --gas auto --gas-adjustment 1.8"
CMD="wasmd --node http://$NODE_URL"

# Deploy Contract
echo "$WASM_BIN_DIR/$WASM_BIN"
echo "🚀 Deploying WASM contract $WASM_BIN_DIR/$WASM_BIN on chain '${CHAIN_ID}' using account '${USER_ADDR}'..."
echo " with cmd : $CMD"
echo "===================================================================="

RES=$($CMD tx wasm store "$WASM_BIN_DIR/$WASM_BIN" --from "$USER_ADDR" $TXFLAG -y --output json)
echo $RES
TX_HASH=$(echo $RES | jq -r '.["txhash"]')

while ! $CMD query tx $TX_HASH &> /dev/null; do
    echo "... 🕐 waiting for contract to deploy from tx hash $TX_HASH"
    sleep 1
done

RES=$($CMD query tx "$TX_HASH" --output json)
CODE_ID=$(echo $RES | jq -r '.logs[0].events[1].attributes[1].value')
echo $CODE_ID

echo ""
echo "🚀 Instantiating contract with the following parameters:"
echo "--------------------------------------------------------"
echo "Label: ${LABEL}"
echo "code_id: ${CODE_ID}"
echo "--------------------------------------------------------"

RES=$($CMD --keyring-backend=test tx wasm instantiate "$CODE_ID" "{}" --from "$USER_ADDR" --label $LABEL $TXFLAG -y --no-admin --output json)
TX_HASH=$(echo $RES | jq -r '.["txhash"]')

echo ""
while ! $CMD query tx $TX_HASH &> /dev/null; do
    echo "... 🕐 waiting for contract to be queryable"
    sleep 1
done

RES=$($CMD query wasm list-contract-by-code "$CODE_ID" --output json)
CONTRACT=$(echo $RES | jq -r '.contracts[0]')

echo "🚀 Successfully deployed and instantiated contract!"
echo "🔗 Chain ID: ${CHAIN_ID}"
echo "🆔 Code ID: ${CODE_ID}"
echo "📌 Contract Address: ${CONTRACT}"
echo "🔑 Contract Key: ${KEY}"
echo "🔖 Contract Label: ${LABEL}"
