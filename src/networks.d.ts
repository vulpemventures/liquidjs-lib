/// <reference types="node" />
import { Network as BitcoinJSNetwork } from 'ecpair/src/networks';
export declare type GenesisBlockHash = Buffer;
export interface Network extends BitcoinJSNetwork {
    blech32: string;
    assetHash: string;
    confidentialPrefix: number;
    genesisBlockHash: GenesisBlockHash;
    name: string;
}
export declare const liquid: Network;
export declare const regtest: Network;
export declare const testnet: Network;
