// package: teleport.terminal.v1
// file: v1/tshd_events_service.proto

/* tslint:disable */
/* eslint-disable */

import * as jspb from "google-protobuf";

export class ReloginRequiredRequest extends jspb.Message { 
    getRootClusterUri(): string;
    setRootClusterUri(value: string): ReloginRequiredRequest;


    hasGatewayCertExpired(): boolean;
    clearGatewayCertExpired(): void;
    getGatewayCertExpired(): GatewayCertExpired | undefined;
    setGatewayCertExpired(value?: GatewayCertExpired): ReloginRequiredRequest;


    getReasonCase(): ReloginRequiredRequest.ReasonCase;

    serializeBinary(): Uint8Array;
    toObject(includeInstance?: boolean): ReloginRequiredRequest.AsObject;
    static toObject(includeInstance: boolean, msg: ReloginRequiredRequest): ReloginRequiredRequest.AsObject;
    static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
    static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
    static serializeBinaryToWriter(message: ReloginRequiredRequest, writer: jspb.BinaryWriter): void;
    static deserializeBinary(bytes: Uint8Array): ReloginRequiredRequest;
    static deserializeBinaryFromReader(message: ReloginRequiredRequest, reader: jspb.BinaryReader): ReloginRequiredRequest;
}

export namespace ReloginRequiredRequest {
    export type AsObject = {
        rootClusterUri: string,
        gatewayCertExpired?: GatewayCertExpired.AsObject,
    }

    export enum ReasonCase {
        REASON_NOT_SET = 0,
    
    GATEWAY_CERT_EXPIRED = 2,

    }

}

export class GatewayCertExpired extends jspb.Message { 
    getGatewayUri(): string;
    setGatewayUri(value: string): GatewayCertExpired;

    getTargetUri(): string;
    setTargetUri(value: string): GatewayCertExpired;


    serializeBinary(): Uint8Array;
    toObject(includeInstance?: boolean): GatewayCertExpired.AsObject;
    static toObject(includeInstance: boolean, msg: GatewayCertExpired): GatewayCertExpired.AsObject;
    static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
    static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
    static serializeBinaryToWriter(message: GatewayCertExpired, writer: jspb.BinaryWriter): void;
    static deserializeBinary(bytes: Uint8Array): GatewayCertExpired;
    static deserializeBinaryFromReader(message: GatewayCertExpired, reader: jspb.BinaryReader): GatewayCertExpired;
}

export namespace GatewayCertExpired {
    export type AsObject = {
        gatewayUri: string,
        targetUri: string,
    }
}

export class ReloginRequiredResponse extends jspb.Message { 

    serializeBinary(): Uint8Array;
    toObject(includeInstance?: boolean): ReloginRequiredResponse.AsObject;
    static toObject(includeInstance: boolean, msg: ReloginRequiredResponse): ReloginRequiredResponse.AsObject;
    static extensions: {[key: number]: jspb.ExtensionFieldInfo<jspb.Message>};
    static extensionsBinary: {[key: number]: jspb.ExtensionFieldBinaryInfo<jspb.Message>};
    static serializeBinaryToWriter(message: ReloginRequiredResponse, writer: jspb.BinaryWriter): void;
    static deserializeBinary(bytes: Uint8Array): ReloginRequiredResponse;
    static deserializeBinaryFromReader(message: ReloginRequiredResponse, reader: jspb.BinaryReader): ReloginRequiredResponse;
}

export namespace ReloginRequiredResponse {
    export type AsObject = {
    }
}
