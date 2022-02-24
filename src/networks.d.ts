import { Network as BitcoinJSNetwork } from 'ecpair/src/networks';
export interface Network extends BitcoinJSNetwork {
    blech32: string;
    assetHash: string;
    confidentialPrefix: number;
}
export declare const liquid: Network;
export declare const regtest: Network;
export declare const testnet: Network;
