#!/usr/bin/env bash

# change with yor own elements-cli config
ecli="nigiri rpc --liquid"

conf_addr_for_reissuance_token=`$ecli getnewaddress`
unconf_addr_random="ert1qtz89cfq54fdgekhu9m759pn3xpr64ek7mmm5ds"

# Issue an asset with supply 0 
issued_asset=`$ecli --liquid issueasset 0 0.00000001 false`
txid=`echo $issued_asset | jq -r .txid`
asset=`echo $issued_asset | jq -r .asset`
token=`echo $issued_asset | jq -r .token`
vin=`echo $issued_asset | jq -r .vin`
entropy=`echo $issued_asset | jq -r .entropy`
echo "txid: $txid"
echo "vin: $vin"
echo "asset: $asset"
echo "token: $token"
echo "entropy: $entropy"
issaunce_tx=`$ecli gettransaction $txid`
assetblinder=`echo $issaunce_tx | jq -r '.details | .[0] | .assetblinder'`
echo "assetblinder: $assetblinder"

$ecli generatetoaddress 1 $conf_addr_for_reissuance_token


# create raw transaction that sends 0.0015 BTC unblinded to someone, attaching the reissuance token already
# the vout 1 is always the reissaunce token (most of the time)
empty_tx=`$ecli createrawtransaction '[{"txid": "'$txid'", "vout": 1}]' '[{"'$conf_addr_for_reissuance_token'":0.00000001, "asset": "'$token'"}, {"'$unconf_addr_random'": 0.0015}]'`


# fund the btc input 
result_funded_tx=`$ecli fundrawtransaction "$empty_tx"`
funded_tx=`echo $result_funded_tx | jq -r .hex`


# attach reissuance stuff
result_reissue_tx=`$ecli rawreissueasset "$funded_tx" '[{"asset_amount":0.0025,"asset_address":"'$unconf_addr_random'", "input_index":0, "asset_blinder":"'$assetblinder'", "entropy":"'$entropy'"}]'`
reissue_tx=`echo $result_reissue_tx | jq -r .hex`


# attach NFT issuance stuff
result_issue_tx=`$ecli rawissueasset "$reissue_tx" '[{"asset_amount":0.00000001,"asset_address":"'$unconf_addr_random'"}]'`
issue_tx=`echo $result_issue_tx | jq -r '.[0] | .hex'`


# blind
blind_tx=`$ecli blindrawtransaction "$issue_tx"`

# sign with wallet
result_signed_tx=`$ecli signrawtransactionwithwallet "$blind_tx"`
signed_tx=`echo $result_signed_tx | jq -r .hex`

echo "signed_tx: $signed_tx"

# broadcast
$ecli sendrawtransaction "$signed_tx"